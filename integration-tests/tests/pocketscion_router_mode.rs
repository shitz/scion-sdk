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
//! Integration tests for PocketSCION in router mode.

use std::{
    num::NonZeroU16,
    time::{Duration, SystemTime},
    vec,
};

use bytes::Bytes;
use pocketscion::{
    runtime::{PocketScionRuntime, PocketScionRuntimeBuilder},
    state::{RouterId, SharedPocketScionState},
};
use scion_proto::{
    address::{IsdAsn, ScionAddr, SocketAddr},
    packet::{ByEndpoint, ScionPacketScmp, ScionPacketUdp},
    path::{DataPlanePath, EncodedStandardPath, HopField, InfoField, StandardPath},
    scmp::{ScmpEchoRequest, ScmpExternalInterfaceDown, ScmpMessage},
    wire_encoding::{WireDecode as _, WireEncodeVec as _},
};
use test_log::test;
use tokio::time::timeout;

struct PocketscionTestEnv {
    pub _pocketscion: PocketScionRuntime,
    pub ia_110: IsdAsn, // 1-ff00:0:110
    pub ia_111: IsdAsn, // 1-ff00:0:111
    pub _rid_110: RouterId,
    pub _rid_111: RouterId,
    pub raddr_110: std::net::SocketAddr,
    #[expect(unused)]
    pub raddr_111: std::net::SocketAddr,
}

async fn minimal_pocketscion_setup() -> PocketscionTestEnv {
    let mut pstate = SharedPocketScionState::new(SystemTime::now());

    let ia_110: IsdAsn = "1-ff00:0:110".parse().unwrap();
    let ia_111: IsdAsn = "1-ff00:0:111".parse().unwrap();

    let rid_110 = pstate.add_router(
        ia_110,
        vec![NonZeroU16::new(1).unwrap(), NonZeroU16::new(2).unwrap()],
    );
    let rid_111 = pstate.add_router(
        ia_111,
        vec![NonZeroU16::new(3).unwrap(), NonZeroU16::new(4).unwrap()],
    );

    let pocketscion = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate.into_state())
        .with_mgmt_listen_addr("127.0.0.1:0".parse().unwrap())
        .start()
        .await
        .expect("Failed to start PocketScion runtime");

    let io_config = pocketscion.api_client().get_io_config().await.unwrap();
    let raddr_110 = io_config
        .router_sockets
        .get(&rid_110)
        .unwrap()
        .parse()
        .unwrap();
    let raddr_111 = io_config
        .router_sockets
        .get(&rid_111)
        .unwrap()
        .parse()
        .unwrap();

    PocketscionTestEnv {
        _pocketscion: pocketscion,
        ia_110,
        ia_111,
        _rid_110: rid_110,
        _rid_111: rid_111,
        raddr_110,
        raddr_111,
    }
}

// Test implementing a simple echo of an echo client and echo server using pocketscion in router
// mode, i.e., without SNAPs.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn echo() {
    let test_env = minimal_pocketscion_setup().await;

    // Bind sockets early to get allocated ports
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind server socket");

    let client_addr = client_socket.local_addr().unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    tracing::info!(
        %client_addr,
        %server_addr,
        "Starting echo test"
    );

    // Spawn a task for the echo server.
    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (len, src_addr) = server_socket
            .recv_from(&mut buf)
            .await
            .expect("Failed to receive packet");
        buf.truncate(len);

        let packet =
            ScionPacketUdp::decode(&mut buf.as_slice()).expect("Failed to decode SCION UDP packet");

        tracing::info!(
            "Server received packet from {}: {}",
            packet.source().unwrap(),
            String::from_utf8_lossy(packet.payload())
        );

        let response_payload = format!("Echo: {}", String::from_utf8_lossy(packet.payload()));
        let response_endp = ByEndpoint {
            source: packet.destination().unwrap(),
            destination: packet.source().unwrap(),
        };
        let response_path = packet
            .headers
            .path
            .to_reversed()
            .expect("Failed to reverse path");
        let response_pkt = ScionPacketUdp::new(
            response_endp,
            response_path.clone(),
            response_payload.into(),
        )
        .expect("Failed to create response packet");

        let resp_raw = response_pkt.encode_to_bytes_vec().concat();

        server_socket
            .send_to(&resp_raw, src_addr)
            .await
            .expect("Failed to send packet");
    });

    // Spawn a task for the client.
    let client_task = tokio::spawn(async move {
        // Construct a simple SCION UDP packet.
        let packet = ScionPacketUdp::new(
            ByEndpoint {
                source: SocketAddr::from_std(test_env.ia_110, client_addr),
                destination: SocketAddr::from_std(test_env.ia_111, server_addr),
            },
            DataPlanePath::Standard(scion_path()),
            b"Hello SCION!".as_ref().into(),
        )
        .expect("Failed to create SCION packet");

        let pkt_raw = packet.encode_to_bytes_vec().concat();

        client_socket
            .send_to(&pkt_raw, test_env.raddr_110)
            .await
            .expect("Failed to send packet");

        let mut recv_buf = vec![0u8; 2048];
        let (len, _) = client_socket
            .recv_from(&mut recv_buf)
            .await
            .expect("Failed to receive packet");
        recv_buf.truncate(len);

        let response_pkt = ScionPacketUdp::decode(&mut recv_buf.as_slice())
            .expect("Failed to decode response SCION UDP packet");

        tracing::info!(
            "Client received packet from {}: {}",
            response_pkt.source().unwrap(),
            String::from_utf8_lossy(response_pkt.payload())
        );

        assert_eq!(
            response_pkt.payload(),
            &Bytes::from(b"Echo: Hello SCION!".as_ref()),
            "Unexpected response payload"
        );
    });

    timeout(Duration::from_secs(5), async move {
        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.expect("Server task panicked");
        client_result.expect("Client task panicked");
    })
    .await
    .expect("Echo test timed out");
}

// Test sending SCMP packets in router mode.
#[test(tokio::test)]
#[ntest::timeout(10_000)]
async fn send_scmp() {
    let test_env = minimal_pocketscion_setup().await;

    // Bind sockets early to get allocated ports
    let sender_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind sender socket");
    let receiver_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind receiver socket");

    let sender_addr = sender_socket.local_addr().unwrap();
    let receiver_addr = receiver_socket.local_addr().unwrap();

    tracing::info!(
        %sender_addr,
        %receiver_addr,
        "Starting SCMP test"
    );

    // Spawn a task for the receiver.
    let receiver_task = tokio::spawn(async move {
        // Receive both SCMP packets
        for _ in 0..2 {
            let mut buf = vec![0u8; 2048];
            let (len, src_addr) = receiver_socket
                .recv_from(&mut buf)
                .await
                .expect("Failed to receive packet");
            buf.truncate(len);

            let packet = ScionPacketScmp::decode(&mut buf.as_slice())
                .expect("Failed to decode SCION SCMP packet");

            tracing::info!(
                "Receiver received SCMP packet from {}: {:?}",
                packet.headers.address.source().unwrap(),
                packet.message
            );

            // Send a simple acknowledgment back
            let response_payload = b"SCMP received";
            let response_pkt = ScionPacketUdp::new(
                ByEndpoint {
                    source: SocketAddr::new(
                        packet.headers.address.destination().unwrap(),
                        receiver_addr.port(),
                    ),
                    destination: SocketAddr::new(
                        packet.headers.address.source().unwrap(),
                        sender_addr.port(),
                    ),
                },
                packet
                    .headers
                    .path
                    .to_reversed()
                    .expect("Failed to reverse path"),
                response_payload.as_ref().into(),
            )
            .expect("Failed to create response packet");

            let resp_raw = response_pkt.encode_to_bytes_vec().concat();

            receiver_socket
                .send_to(&resp_raw, src_addr)
                .await
                .expect("Failed to send packet");
        }
    });

    // Spawn a task for the sender.
    let sender_task = tokio::spawn(async move {
        let dp_path = DataPlanePath::Standard(scion_path());

        // Send SCMP echo request with correct identifier (receiver's port)
        let echo_request = ScmpMessage::EchoRequest(ScmpEchoRequest::new(
            receiver_addr.port(),
            1,
            Bytes::from_static(b"echo test data"),
        ));

        let echo_packet = ScionPacketScmp::new(
            ByEndpoint {
                source: ScionAddr::new(test_env.ia_110, sender_addr.ip().into()),
                destination: ScionAddr::new(test_env.ia_111, receiver_addr.ip().into()),
            },
            dp_path.clone(),
            echo_request,
        )
        .expect("Failed to create SCMP echo packet");

        let echo_raw = echo_packet.encode_to_bytes_vec().concat();
        sender_socket
            .send_to(&echo_raw, test_env.raddr_110)
            .await
            .expect("Failed to send SCMP echo packet");

        // Send SCMP external interface down with quoted UDP packet
        // Create a UDP packet that will be quoted in the SCMP error
        let quoted_udp = ScionPacketUdp::new(
            ByEndpoint {
                source: SocketAddr::from_std(test_env.ia_111, receiver_addr), // receiver as source
                destination: SocketAddr::from_std(test_env.ia_110, sender_addr), // sender as destination
            },
            dp_path.clone(),
            Bytes::from_static(b"quoted payload"),
        )
        .expect("Failed to create quoted UDP packet");

        let interface_down = ScmpMessage::ExternalInterfaceDown(ScmpExternalInterfaceDown::new(
            test_env.ia_110,
            42,
            quoted_udp.encode_to_bytes_vec().concat().into(),
        ));

        let interface_down_packet = ScionPacketScmp::new(
            ByEndpoint {
                source: ScionAddr::new(test_env.ia_110, sender_addr.ip().into()),
                destination: ScionAddr::new(test_env.ia_111, receiver_addr.ip().into()),
            },
            dp_path,
            interface_down,
        )
        .expect("Failed to create SCMP interface down packet");

        let interface_down_raw = interface_down_packet.encode_to_bytes_vec().concat();
        sender_socket
            .send_to(&interface_down_raw, test_env.raddr_110)
            .await
            .expect("Failed to send SCMP interface down packet");

        // Wait for acknowledgments
        for _ in 0..2 {
            let mut recv_buf = vec![0u8; 2048];
            let (len, _) = sender_socket
                .recv_from(&mut recv_buf)
                .await
                .expect("Failed to receive acknowledgment");
            recv_buf.truncate(len);

            let response_pkt = ScionPacketUdp::decode(&mut recv_buf.as_slice())
                .expect("Failed to decode response SCION UDP packet");

            tracing::info!(
                "Sender received acknowledgment from {}: {}",
                response_pkt.source().unwrap(),
                String::from_utf8_lossy(response_pkt.payload())
            );

            assert_eq!(
                response_pkt.payload(),
                &Bytes::from(b"SCMP received".as_ref()),
                "Unexpected acknowledgment payload"
            );
        }
    });

    timeout(Duration::from_secs(5), async move {
        let (receiver_result, sender_result) = tokio::join!(receiver_task, sender_task);
        receiver_result.expect("Receiver task panicked");
        sender_result.expect("Sender task panicked");
    })
    .await
    .expect("SCMP test timed out");
}

fn scion_path() -> EncodedStandardPath {
    let info = InfoField {
        cons_dir: true,
        ..Default::default()
    };
    let hop1 = HopField {
        cons_egress: 2,
        ..Default::default()
    };
    let hop2 = HopField {
        cons_ingress: 3,
        ..Default::default()
    };

    let mut path = StandardPath::new();
    path.add_segment(info, vec![hop1, hop2])
        .expect("Failed to add segment to SCION path");
    path.into()
}
