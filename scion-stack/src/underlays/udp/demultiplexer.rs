// Copyright 2025 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{collections::HashMap, net, sync::Arc};

use bytes::BytesMut;
use scion_proto::{
    address::{IsdAsn, SocketAddr},
    datagram::UdpMessage,
    packet::ScionPacketRaw,
    scmp::SCMP_PROTOCOL_NUMBER,
    wire_encoding::WireDecode as _,
};
use tokio::{
    net::UdpSocket,
    sync::{
        Mutex,
        mpsc::{Receiver, Sender, error::TrySendError},
        oneshot,
    },
};
use tracing::{debug, error, warn};

use crate::scionstack::{ScionSocketBindError, SocketKind};

const UDP_DATAGRAM_BUFFER_SIZE: usize = 65535;

/// Demultiplexer coordinates the creation of OS UDP sockets and their [SocketDriver]s.
pub struct Demultiplexer(Arc<Mutex<DemultiplexerState>>);

impl Demultiplexer {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(DemultiplexerState::new())))
    }

    /// Register a new receiver for the underlay socket that is bound on the host address of the
    /// given bind_addr.
    ///
    /// Parameters:
    /// - bind_addr: The address to bind the underlay socket to. The ISD-AS number must not be a
    ///   wildcard and service addresses are not supported. If the port is 0, the port will be
    ///   assigned by the OS.
    /// - socket_kind: The kind of socket to register.
    /// - sender: The sender to send received packets to.
    ///
    /// Returns:
    /// - The Arc<UdpSocket> of the underlay socket.
    pub async fn register(
        &self,
        bind_addr: SocketAddr,
        socket_kind: SocketKind,
        sender: Sender<ScionPacketRaw>,
    ) -> Result<Arc<UdpSocket>, ScionSocketBindError> {
        self.0
            .lock()
            .await
            .register(bind_addr, socket_kind, sender)
            .await
    }

    #[cfg(test)]
    async fn get_socket_driver_entry(&self, addr: &net::SocketAddr) -> Option<SocketDriverControl> {
        self.0
            .lock()
            .await
            .get_socket_driver_entry(addr)
            .map(|entry| entry.socket_driver_control.clone())
    }
}

/// DemultiplexerState manages the UDP sockets along with their drivers.
struct DemultiplexerState {
    socket_drivers: HashMap<net::SocketAddr, SocketDriverEntry>,
}

struct SocketDriverEntry {
    socket_driver_control: SocketDriverControl,
    underlay_receiver: Arc<UdpSocket>,
}

impl DemultiplexerState {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            socket_drivers: HashMap::new(),
        }
    }

    pub async fn register(
        &mut self,
        bind_addr: SocketAddr,
        socket_kind: SocketKind,
        sender: Sender<ScionPacketRaw>,
    ) -> Result<Arc<UdpSocket>, ScionSocketBindError> {
        // Service addresses are not supported.
        let local_addr =
            bind_addr
                .local_address()
                .ok_or(ScionSocketBindError::InvalidBindAddress(
                    bind_addr,
                    "Service addresses can't be bound".to_string(),
                ))?;

        if bind_addr.isd_asn().is_wildcard() {
            return Err(ScionSocketBindError::InvalidBindAddress(
                bind_addr,
                "Wildcard ISD-AS numbers are not supported".to_string(),
            ));
        }

        if let Some(entry) = self.socket_drivers.get(&local_addr) {
            // Entry exists, try to register with existing socket driver
            let (tx, rx) = oneshot::channel();
            let control_msg = SocketDriverControlMessage::RegisterReceiver(
                ReceiverKey {
                    isd_asn: bind_addr.isd_asn(),
                    kind: socket_kind.clone(),
                },
                sender.clone(),
                tx,
            );

            match entry.socket_driver_control.try_send(control_msg) {
                Ok(()) => {
                    // Successfully sent control message, wait for response
                    match rx.await {
                        Ok(Ok(())) => return Ok(entry.underlay_receiver.clone()),
                        Ok(Err(_)) => {
                            return Err(ScionSocketBindError::PortAlreadyInUse(bind_addr.port()));
                        }
                        Err(_) => {} // SocketDriver is done, remove the entry.
                    }
                }
                Err(TrySendError::Full(_)) => {
                    warn!(
                        "SocketDriver control channel is full, indicates that the SocketDriver has a bug and is stuck"
                    );
                    return Err(ScionSocketBindError::Internal(
                        "SocketDriver control channel is full, this should never happen"
                            .to_string(),
                    ));
                }
                Err(TrySendError::Closed(_)) => {} // SocketDriver is done, remove the entry.
            }
            self.socket_drivers.remove(&local_addr);
        }

        let underlay_socket =
            Arc::new(tokio::net::UdpSocket::bind(local_addr).await.map_err(|e| {
                match e.kind() {
                    std::io::ErrorKind::AddrInUse => {
                        ScionSocketBindError::PortAlreadyInUse(local_addr.port())
                    }
                    std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::InvalidInput => {
                        ScionSocketBindError::InvalidBindAddress(
                            bind_addr,
                            format!("Failed to bind socket: {e:#}"),
                        )
                    }
                    _ => ScionSocketBindError::Other(Box::new(e)),
                }
            })?);

        // Create socket driver
        let actual_local_addr = underlay_socket.local_addr().map_err(|e| {
            ScionSocketBindError::InvalidBindAddress(
                bind_addr,
                format!("Failed to get local address: {e}"),
            )
        })?;

        let (control_tx, control_rx) = tokio::sync::mpsc::channel(100);
        let socket_driver = SocketDriver::new(
            control_rx,
            sender,
            ReceiverKey {
                isd_asn: bind_addr.isd_asn(),
                kind: socket_kind,
            },
            underlay_socket.clone(),
            actual_local_addr,
        );

        // Start the socket driver task. We do not store the task handle because the
        // socket driver will exit on its own.
        tokio::spawn(socket_driver.run());

        // Create and insert the new entry
        self.socket_drivers.insert(
            actual_local_addr,
            SocketDriverEntry {
                socket_driver_control: control_tx,
                underlay_receiver: underlay_socket.clone(),
            },
        );

        Ok(underlay_socket)
    }

    #[cfg(test)]
    /// Get the socket driver entry for the given address for testing purposes.
    fn get_socket_driver_entry(&self, addr: &net::SocketAddr) -> Option<&SocketDriverEntry> {
        self.socket_drivers.get(addr)
    }
}

type SocketDriverControl = Sender<SocketDriverControlMessage>;

enum SocketDriverControlMessage {
    /// Register a new receiver for the given ISD-AS number and socket kind.
    /// The sender will be cleaned up when the receiver is closed.
    /// The response is sent on the oneshot channel.
    RegisterReceiver(
        ReceiverKey,
        Sender<ScionPacketRaw>,
        oneshot::Sender<Result<(), RegistrationError>>,
    ),
}

/// SocketDriver handles receiving packets from the underlay socket and dispatching them to the
/// registered receivers.
///
/// ## Lifecycle
///
/// It is started as an independent tokio task and accepts control messages via a bounded
/// channel.
///
/// The SocketDriver shuts down when one of the following conditions is met:
///
/// - The control channel is closed.
/// - All registered receivers are closed.
/// - An error occurs while receiving a packet from the underlay socket i.e. the underlay socket is
///   closed.
///
/// ## Dispatching
///
/// The SocketDriver dispatches packets for a specific net::SocketAddr.
/// Receivers can be registered for different ISD-AS numbers and socket kinds.
///
/// Packets are dispatched based on their destination ISD-AS number and NextHeader field.
/// - Udp packets are dispatched to registered UDP and Raw receivers.
/// - Scmp packets are dispatched to registered SCMP and Raw receivers.
/// - Other packets are dispatched to registered Raw receivers.
struct SocketDriver {
    control_rx: Receiver<SocketDriverControlMessage>,
    receivers: Receivers,
    underlay_socket: std::sync::Arc<UdpSocket>,
    host_bind_addr: net::SocketAddr,
}

impl SocketDriver {
    fn new(
        control_rx: Receiver<SocketDriverControlMessage>,
        initial_receiver: Sender<ScionPacketRaw>,
        initial_receiver_key: ReceiverKey,
        underlay_receiver: std::sync::Arc<UdpSocket>,
        bind_addr: net::SocketAddr,
    ) -> Self {
        Self {
            control_rx,
            receivers: Receivers::new(initial_receiver_key, initial_receiver),
            underlay_socket: underlay_receiver,
            host_bind_addr: bind_addr,
        }
    }
    async fn run(mut self) {
        let mut recv_buffer = vec![0u8; UDP_DATAGRAM_BUFFER_SIZE];

        loop {
            tokio::select! {
                control_msg = self.control_rx.recv() => {
                    match control_msg {
                        Some(SocketDriverControlMessage::RegisterReceiver(key, sender, tx)) => {
                            _ = tx.send(self.receivers.register(key, sender));
                        }
                        None => {
                            debug!(socket_addr=%self.host_bind_addr, "Socket driver shutting down because the control channel is closed, this means the scion stack was dropped");
                            break;
                        }
                    }
                }
                _ = self.receivers.all_closed() => {
                    // If all senders are closed, the socket driver is done.
                    debug!(socket_addr=%self.host_bind_addr, "Socket driver shutting down because all senders are closed");
                    break;
                }
                result = self.underlay_socket.recv(&mut recv_buffer) => {
                    match result {
                        Ok(n) => {
                            let mut bytes_mut = BytesMut::from(&recv_buffer[..n]);
                            self.handle_recv(&mut bytes_mut);
                        }
                        Err(e) => {
                            error!("Error receiving datagram: {}", e);
                            // If the underlay receiver is closed, the socket driver is done.
                            debug!(socket_addr=%self.host_bind_addr, "Socket driver shutting down because underlay receiver is closed");
                            break;
                        }
                    }
                }
            }
        }
    }

    fn handle_recv(&mut self, raw_data: &mut BytesMut) {
        let packet = match ScionPacketRaw::decode(raw_data) {
            Ok(packet) => packet,
            Err(e) => {
                debug!(error = %e, "Failed to decode SCION packet");
                return;
            }
        };

        // Make sure the packet SCION header destination address matches the bound address.
        match packet.headers.address.destination() {
            Some(dst) => {
                if dst.host() != self.host_bind_addr.ip().into() {
                    debug!(
                        socket_addr=%self.host_bind_addr,
                        src=%packet.headers.address.ia.source,
                        dst=%dst,
                        "Dropping packet with non-matching destination host",
                    );
                    return;
                }
            }
            None => {
                debug!(
                    socket_addr=%self.host_bind_addr,
                    src=%packet.headers.address.ia.source,
                    dst=%packet.headers.address.ia.destination,
                    "Dropping packet with invalid destination address",
                );
                return;
            }
        }

        // Classify the SCION packet
        match packet.headers.common.next_header {
            UdpMessage::PROTOCOL_NUMBER => {
                self.receivers.dispatch_udp_packet(packet);
            }
            SCMP_PROTOCOL_NUMBER => {
                self.receivers.dispatch_scmp_packet(packet);
            }
            _ => {
                self.receivers.dispatch_raw_packet(packet);
            }
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct ReceiverKey {
    isd_asn: IsdAsn,
    kind: SocketKind,
}

struct Receivers {
    map: HashMap<ReceiverKey, Sender<ScionPacketRaw>>,
}

impl Receivers {
    fn new(initial_receiver_key: ReceiverKey, initial_receiver: Sender<ScionPacketRaw>) -> Self {
        Self {
            map: HashMap::from([(initial_receiver_key, initial_receiver)]),
        }
    }

    fn do_dispatch_packet(&mut self, a: ReceiverKey, packet: ScionPacketRaw) {
        // Clone senders (or take references to Arc<Sender> if that's your setup)
        let raw_key = ReceiverKey {
            isd_asn: a.isd_asn,
            kind: SocketKind::Raw,
        };
        let sender_a = self.map.get(&a).cloned();
        let sender_raw = self.map.get(&raw_key).cloned();

        let mut send_to =
            |key: ReceiverKey, sender: Sender<ScionPacketRaw>, packet: ScionPacketRaw| {
                match sender.try_send(packet) {
                    Ok(_) => (),
                    Err(TrySendError::Closed(_)) => {
                        self.map.remove(&key);
                    }
                    Err(TrySendError::Full(_)) => {
                        warn!("Receive channel is full, dropping packet");
                    }
                }
            };

        match (sender_a, sender_raw) {
            (Some(sa), Some(sb)) => {
                send_to(a, sa, packet.clone());
                send_to(raw_key, sb, packet);
            }
            (Some(sa), None) => {
                send_to(a, sa, packet);
            }
            (None, Some(sb)) => {
                send_to(raw_key, sb, packet);
            }
            (None, None) => {
                error!("No receivers registered for packet");
            }
        }
    }

    fn dispatch_udp_packet(&mut self, udp_packet: ScionPacketRaw) {
        let dst = udp_packet.headers.address.ia.destination;
        self.do_dispatch_packet(
            ReceiverKey {
                isd_asn: dst,
                kind: SocketKind::Udp,
            },
            udp_packet,
        );
    }

    fn dispatch_scmp_packet(&mut self, scmp_packet: ScionPacketRaw) {
        let dst = scmp_packet.headers.address.ia.destination;
        self.do_dispatch_packet(
            ReceiverKey {
                isd_asn: dst,
                kind: SocketKind::Scmp,
            },
            scmp_packet,
        );
    }

    fn dispatch_raw_packet(&mut self, raw_packet: ScionPacketRaw) {
        let key = ReceiverKey {
            isd_asn: raw_packet.headers.address.ia.destination,
            kind: SocketKind::Raw,
        };

        match self.map.get(&key) {
            Some(sender) => {
                match sender.try_send(raw_packet) {
                    Ok(_) => (),
                    Err(TrySendError::Full(_)) => {
                        warn!("Receive channel is full, dropping packet");
                    }
                    Err(TrySendError::Closed(_)) => {
                        self.map.remove(&key);
                    }
                }
            }
            None => {
                warn!("No receivers registered for packet");
            }
        }
    }

    fn register(
        &mut self,
        key: ReceiverKey,
        sender: Sender<ScionPacketRaw>,
    ) -> Result<(), RegistrationError> {
        if let Some(sender) = self.map.get(&key)
            && !sender.is_closed()
        {
            return Err(RegistrationError::PortAlreadyInUse);
        }
        self.map.insert(key, sender);
        Ok(())
    }

    /// Resolves when all senders are closed.
    async fn all_closed(&self) {
        for (_, sender) in self.map.iter() {
            sender.closed().await;
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

#[derive(thiserror::Error, Debug)]
enum RegistrationError {
    #[error("port already in use")]
    PortAlreadyInUse,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::{Bytes, BytesMut};
    use scion_proto::{
        address::{Asn, HostAddr, Isd, IsdAsn, ScionAddr, ServiceAddr, SocketAddr},
        datagram::UdpMessage,
        packet::{ByEndpoint, ScionPacketRaw, ScionPacketScmp, ScionPacketUdp},
        path::{DataPlanePath, EncodedStandardPath},
        scmp::{ScmpEchoRequest, ScmpMessage},
        wire_encoding::{WireDecode, WireEncodeVec},
    };
    use tokio::{net::UdpSocket, sync::mpsc, time::timeout};

    use super::*;
    use crate::scionstack::SocketKind;

    // Test constants
    const TEST_IA: IsdAsn = IsdAsn::new(Isd::new(1), Asn::new(0xff00_0000_0100));

    fn test_socket_addr() -> SocketAddr {
        "[1-ff00:0:100,127.0.0.1]:0".parse().unwrap()
    }

    fn simple_path() -> DataPlanePath {
        let mut path_raw = BytesMut::with_capacity(36);
        path_raw.extend_from_slice(&[0x00, 0x00, 0x20, 0x00]); // PathType = OneHopPath
        path_raw.extend_from_slice(&[0_u8; 32]); // 32 bytes of zeros for OneHopPath
        DataPlanePath::Standard(EncodedStandardPath::decode(&mut path_raw.freeze()).unwrap())
    }

    fn udp_test_packet(dst: SocketAddr) -> ScionPacketRaw {
        let endpoints = ByEndpoint {
            source: "[1-ff00:0:111,127.0.0.1]:9000".parse().unwrap(),
            destination: dst,
        };

        let udp_packet = ScionPacketUdp::new(
            endpoints,
            simple_path(),
            Bytes::from_static(b"test payload"),
        )
        .unwrap();

        udp_packet.into()
    }

    fn scmp_test_packet(dst: ScionAddr) -> ScionPacketRaw {
        let endpoints = ByEndpoint {
            source: "1-ff00:0:111,127.0.0.1".parse().unwrap(),
            destination: dst,
        };

        let echo_request =
            ScmpMessage::EchoRequest(ScmpEchoRequest::new(1, 1, Bytes::from_static(b"ping")));

        let scmp_packet = ScionPacketScmp::new(endpoints, simple_path(), echo_request).unwrap();

        scmp_packet.into()
    }

    fn raw_test_packet(dst: ScionAddr) -> ScionPacketRaw {
        let endpoints = ByEndpoint {
            source: "1-ff00:0:111,127.0.0.1".parse().unwrap(),
            destination: dst,
        };

        ScionPacketRaw::new(
            endpoints,
            simple_path(),
            Bytes::from_static(b"raw payload"),
            42, // Unknown protocol number
            Default::default(),
        )
        .unwrap()
    }

    // Unit tests for Receivers struct
    mod receivers_tests {
        use super::*;

        #[test_log::test(tokio::test)]
        async fn dispatch_udp_to_raw_fanout() {
            // Setup: Create channels for all three receiver types
            let (udp_tx, mut udp_rx) = mpsc::channel(1);
            let (scmp_tx, mut scmp_rx) = mpsc::channel(1);
            let (raw_tx, mut raw_rx) = mpsc::channel(1);

            let udp_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Udp,
            };
            let scmp_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Scmp,
            };
            let raw_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Raw,
            };

            let mut receivers = Receivers::new(udp_key.clone(), udp_tx);
            receivers.register(scmp_key, scmp_tx).unwrap();
            receivers.register(raw_key, raw_tx).unwrap();

            // Create and dispatch UDP packet
            let packet = udp_test_packet(test_socket_addr());
            receivers.dispatch_udp_packet(packet.clone());

            // Expect: UDP and Raw receivers get a copy of the packet, SCMP does not
            let udp_received = udp_rx.recv().await.unwrap();
            let raw_received = raw_rx.recv().await.unwrap();

            // SCMP receiver should timeout (not receive the packet)
            let scmp_result = timeout(Duration::from_millis(100), scmp_rx.recv()).await;
            assert!(
                scmp_result.is_err(),
                "SCMP receiver should not receive UDP packet"
            );

            assert_eq!(
                udp_received.headers.common.next_header,
                UdpMessage::PROTOCOL_NUMBER
            );
            assert_eq!(
                raw_received.headers.common.next_header,
                UdpMessage::PROTOCOL_NUMBER
            );
            assert_eq!(udp_received.payload, packet.payload);
            assert_eq!(raw_received.payload, packet.payload);
        }

        #[test_log::test(tokio::test)]
        async fn dispatch_scmp_to_raw_fanout() {
            // Setup: Create channels for all three receiver types
            let (udp_tx, mut udp_rx) = mpsc::channel(1);
            let (scmp_tx, mut scmp_rx) = mpsc::channel(1);
            let (raw_tx, mut raw_rx) = mpsc::channel(1);

            let udp_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Udp,
            };
            let scmp_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Scmp,
            };
            let raw_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Raw,
            };

            let mut receivers = Receivers::new(scmp_key.clone(), scmp_tx);
            receivers.register(udp_key, udp_tx).unwrap();
            receivers.register(raw_key, raw_tx).unwrap();

            // Create and dispatch SCMP packet
            let packet = scmp_test_packet(test_socket_addr().scion_address());
            receivers.dispatch_scmp_packet(packet.clone());

            // Expect: SCMP and Raw receivers get a copy, UDP does not
            let scmp_received = scmp_rx.recv().await.unwrap();
            let raw_received = raw_rx.recv().await.unwrap();

            // UDP receiver should timeout (not receive the packet)
            let udp_result = timeout(Duration::from_millis(100), udp_rx.recv()).await;
            assert!(
                udp_result.is_err(),
                "UDP receiver should not receive SCMP packet"
            );

            assert_eq!(scmp_received, packet);
            assert_eq!(raw_received, packet);
        }

        #[test_log::test(tokio::test)]
        async fn dispatch_raw_packet() {
            // Setup: Create channels for all three receiver types
            let (udp_tx, mut udp_rx) = mpsc::channel(1);
            let (scmp_tx, mut scmp_rx) = mpsc::channel(1);
            let (raw_tx, mut raw_rx) = mpsc::channel(1);

            let udp_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Udp,
            };
            let scmp_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Scmp,
            };
            let raw_key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Raw,
            };

            let mut receivers = Receivers::new(raw_key, raw_tx);
            receivers.register(udp_key, udp_tx).unwrap();
            receivers.register(scmp_key, scmp_tx).unwrap();

            let packet = raw_test_packet(test_socket_addr().scion_address());
            receivers.dispatch_raw_packet(packet.clone());

            // Expect: Only Raw receiver gets it, UDP and SCMP do not
            let received = raw_rx.recv().await.unwrap();

            // UDP and SCMP receivers should timeout (not receive the packet)
            let udp_result = timeout(Duration::from_millis(100), udp_rx.recv()).await;
            assert!(
                udp_result.is_err(),
                "UDP receiver should not receive raw packet"
            );

            let scmp_result = timeout(Duration::from_millis(100), scmp_rx.recv()).await;
            assert!(
                scmp_result.is_err(),
                "SCMP receiver should not receive raw packet"
            );

            assert_eq!(packet, received);
        }

        #[test_log::test(tokio::test)]
        async fn no_receiver_case() {
            // Setup: Register no matching receivers
            let (dummy_tx, _dummy_rx) = mpsc::channel(1);
            let dummy_key = ReceiverKey {
                isd_asn: IsdAsn::new(Isd::new(2), Asn::new(0x220)), // Different IA
                kind: SocketKind::Udp,
            };

            let mut receivers = Receivers::new(dummy_key, dummy_tx);

            // Call dispatch_raw_packet with no matching receiver
            let packet = raw_test_packet(test_socket_addr().scion_address());
            receivers.dispatch_raw_packet(packet);

            // Expect: Nothing is sent, only a warning is logged.
            // This test mainly ensures no panic occurs
        }

        #[test_log::test]
        fn receiver_port_already_in_use() {
            // Setup: Register first receiver
            let (tx1, _rx1) = mpsc::channel(1);
            let (tx2, _rx2) = mpsc::channel(1);

            let key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Udp,
            };

            let mut receivers = Receivers::new(key.clone(), tx1);

            // Try to register second receiver with same key
            let result = receivers.register(key, tx2);

            // Expect: Second registration returns PortAlreadyInUse
            assert!(matches!(result, Err(RegistrationError::PortAlreadyInUse)));
        }

        #[test_log::test(tokio::test)]
        async fn drop_channel_cleaned_up_automatically() {
            // Setup: Register receiver and drop the receiver side
            let (tx, rx) = mpsc::channel(1);

            let key = ReceiverKey {
                isd_asn: TEST_IA,
                kind: SocketKind::Udp,
            };

            let mut receivers = Receivers::new(key, tx);
            drop(rx); // Drop receiver side

            // Call dispatch_udp_packet
            let packet = udp_test_packet(test_socket_addr());
            receivers.dispatch_udp_packet(packet);

            // Make sure the receiver is cleaned up.
            assert_eq!(receivers.len(), 0);
        }
    }

    // End-to-end tests for Demultiplexer
    mod demultiplexer_tests {
        use super::*;

        #[test_log::test(tokio::test)]
        async fn udp_dispatch() {
            // Setup: Register both UDP and Raw receivers on same bind address
            let demux = Demultiplexer::new();
            let (udp_tx, mut udp_rx) = mpsc::channel(10);
            let (scmp_tx, mut scmp_rx) = mpsc::channel(10);
            let (raw_tx, mut raw_rx) = mpsc::channel(10);

            let mut bind_addr = test_socket_addr();
            let socket = demux
                .register(bind_addr, SocketKind::Udp, udp_tx)
                .await
                .expect("Failed to register UDP receiver");
            bind_addr.set_port(socket.local_addr().unwrap().port());

            demux
                .register(bind_addr, SocketKind::Scmp, scmp_tx)
                .await
                .expect("Failed to register SCMP receiver");

            demux
                .register(bind_addr, SocketKind::Raw, raw_tx)
                .await
                .expect("Failed to register Raw receiver");

            // Send SCION/UDP packet with correct destination
            let local_addr = socket.local_addr().unwrap();
            let packet = udp_test_packet(bind_addr);
            let encoded = packet.encode_to_bytes_vec().concat();

            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client_socket.send_to(&encoded, local_addr).await.unwrap();

            // Expect: Both receivers get a copy
            let udp_received = timeout(Duration::from_millis(100), udp_rx.recv())
                .await
                .expect("Timeout waiting for UDP packet")
                .expect("UDP channel closed");

            assert_eq!(packet, udp_received);

            let raw_received = timeout(Duration::from_millis(100), raw_rx.recv())
                .await
                .expect("Timeout waiting for Raw packet")
                .expect("Raw channel closed");

            assert_eq!(packet, raw_received);

            let err = timeout(Duration::from_millis(100), scmp_rx.recv()).await;
            assert!(err.is_err());
        }

        #[test_log::test(tokio::test)]
        async fn scmp_dispatch() {
            // Setup: Register SCMP and Raw receivers
            let demux = Demultiplexer::new();
            let (udp_tx, mut udp_rx) = mpsc::channel(10);
            let (scmp_tx, mut scmp_rx) = mpsc::channel(10);
            let (raw_tx, mut raw_rx) = mpsc::channel(10);

            let mut bind_addr = test_socket_addr();
            let socket = demux
                .register(bind_addr, SocketKind::Scmp, scmp_tx)
                .await
                .expect("Failed to register SCMP receiver");
            bind_addr.set_port(socket.local_addr().unwrap().port());

            demux
                .register(bind_addr, SocketKind::Raw, raw_tx)
                .await
                .expect("Failed to register Raw receiver");

            demux
                .register(bind_addr, SocketKind::Udp, udp_tx)
                .await
                .expect("Failed to register UDP receiver");

            // Send SCION/SCMP packet with correct destination
            let local_addr = socket.local_addr().unwrap();
            let packet = scmp_test_packet(bind_addr.scion_address());
            let encoded = packet.encode_to_bytes_vec().concat();

            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client_socket.send_to(&encoded, local_addr).await.unwrap();

            // Expect: Both receivers get a copy
            let scmp_received = timeout(Duration::from_millis(100), scmp_rx.recv())
                .await
                .expect("Timeout waiting for SCMP packet")
                .expect("SCMP channel closed");

            assert_eq!(packet, scmp_received);

            let raw_received = timeout(Duration::from_millis(100), raw_rx.recv())
                .await
                .expect("Timeout waiting for Raw packet")
                .expect("Raw channel closed");

            assert_eq!(packet, raw_received);

            let err = timeout(Duration::from_millis(100), udp_rx.recv()).await;
            assert!(err.is_err());
        }

        #[test_log::test(tokio::test)]
        async fn raw_fallback_dispatch() {
            // Setup: Register only Raw receiver
            let demux = Demultiplexer::new();
            let (raw_tx, mut raw_rx) = mpsc::channel(10);

            let bind_addr = test_socket_addr();
            let socket = demux
                .register(bind_addr, SocketKind::Raw, raw_tx)
                .await
                .expect("Failed to register Raw receiver");

            // Send SCION packet with unknown next_header and correct destination
            let local_addr = socket.local_addr().unwrap();
            let packet = raw_test_packet(bind_addr.scion_address());
            let encoded = packet.encode_to_bytes_vec().concat();

            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client_socket.send_to(&encoded, local_addr).await.unwrap();

            // Expect: Raw receiver gets it
            let received = timeout(Duration::from_millis(100), raw_rx.recv())
                .await
                .expect("Timeout waiting for packet")
                .expect("Channel closed");

            assert_eq!(packet, received);
        }

        #[test_log::test(tokio::test)]
        async fn error_addr_already_in_use() {
            // Setup: Register first receiver
            let demux = Demultiplexer::new();
            let (tx1, _rx1) = mpsc::channel(10);
            let (tx2, _rx2) = mpsc::channel(10);

            let mut bind_addr = test_socket_addr();
            let socket1 = demux
                .register(bind_addr, SocketKind::Udp, tx1)
                .await
                .expect("Failed to register first receiver");
            bind_addr.set_port(socket1.local_addr().unwrap().port());

            // Try to register another receiver for the same IA and socket kind
            let result = demux.register(bind_addr, SocketKind::Udp, tx2).await;

            // Expect: Returns AddrInUse error
            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(
                matches!(error, ScionSocketBindError::PortAlreadyInUse(_)),
                "Expected PortAlreadyInUse error, got {error:?}",
            );
        }

        #[test_log::test(tokio::test)]
        async fn graceful_shutdown_when_all_receivers_closed() {
            // Setup: Register a receiver and get the socket driver handle
            let demux = Demultiplexer::new();
            let (tx, rx) = mpsc::channel(10);

            let bind_addr = test_socket_addr();
            let socket = demux
                .register(bind_addr, SocketKind::Udp, tx)
                .await
                .expect("Failed to register receiver");

            // Get the control channel for the socket driver
            let local_addr = socket.local_addr().unwrap();
            let control_channel = demux
                .get_socket_driver_entry(&local_addr)
                .await
                .expect("Socket driver entry should exist");

            // Drop the receiver side to close the channel
            drop(rx);

            // Wait for the control channel to be closed, indicating the SocketDriver is shut down
            control_channel.closed().await;

            // Try to register a new receiver on the same address
            let (new_tx, _new_rx) = mpsc::channel(10);
            let result = demux.register(bind_addr, SocketKind::Udp, new_tx).await;

            // Should succeed since the old driver should have terminated
            assert!(result.is_ok());
        }

        #[test_log::test(tokio::test)]
        async fn invalid_packet() {
            // Setup: Register receiver
            let demux = Demultiplexer::new();
            let (tx, mut rx) = mpsc::channel(10);

            let bind_addr = test_socket_addr();
            let socket = demux
                .register(bind_addr, SocketKind::Raw, tx)
                .await
                .expect("Failed to register receiver");

            // Send garbage bytes
            let garbage = b"this is not a valid SCION packet";
            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local_addr = socket.local_addr().unwrap();
            client_socket.send_to(garbage, local_addr).await.unwrap();

            // Expect: No panic, no channel messages delivered
            let result = timeout(Duration::from_millis(50), rx.recv()).await;
            assert!(result.is_err()); // Timeout should occur, no message received
        }

        #[test_log::test(tokio::test)]
        async fn error_service_addresses_not_supported() {
            // Setup: Try to register with a service address
            let demux = Demultiplexer::new();
            let (tx, _rx) = mpsc::channel(10);

            let service_addr = SocketAddr::new(
                ScionAddr::new(TEST_IA, HostAddr::Svc(ServiceAddr::CONTROL)),
                123,
            );

            // Expect: Registration fails
            let result = demux.register(service_addr, SocketKind::Udp, tx).await;
            let error = result.unwrap_err();
            assert!(
                matches!(error, ScionSocketBindError::InvalidBindAddress(_, _)),
                "Expected InvalidBindAddress error, got {error:?}",
            );
        }

        #[test_log::test(tokio::test)]
        async fn packet_with_non_matching_destination_discarded() {
            // Setup: Create demultiplexer and register UDP receiver
            let demux = Demultiplexer::new();
            let (tx, mut rx) = mpsc::channel(10);

            let bind_addr = test_socket_addr();
            let socket = demux
                .register(bind_addr, SocketKind::Udp, tx)
                .await
                .expect("Failed to register receiver");

            // Build and encode a SCION/UDP packet with a different destination IP
            let packet = udp_test_packet("[2-ff00:0:200,127.0.0.1]:1234".parse().unwrap());
            let encoded = packet.encode_to_bytes_vec().concat();

            // Send packet to the socket
            let sending_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sending_socket
                .send_to(&encoded, socket.local_addr().unwrap())
                .await
                .unwrap();

            // Expect: Channel should not receive the packet (timeout after 100ms)
            let result = timeout(Duration::from_millis(100), rx.recv()).await;
            assert!(
                result.is_err(),
                "Packet with non-matching destination should be discarded"
            );
        }
    }
}
