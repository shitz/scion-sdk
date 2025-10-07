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
//! Tunnel gateway.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use bytes::Bytes;
use quinn::{Connection, Endpoint as QuinnEndpoint};
use scion_proto::{
    address::{EndhostAddr, HostAddr, IsdAsn, ScionAddr},
    packet::{ByEndpoint, CommonHeader, ScionPacketScmp, ScmpEncodeError},
    path::DataPlanePath,
    scmp::{ParameterProblemCode, ScmpMessage, ScmpParameterProblem},
    wire_encoding::WireEncodeVec,
};
use serde::Deserialize;
use token_validator::validator::Token;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, instrument};

use crate::{
    dispatcher::Dispatcher,
    tunnel_gateway::{
        metrics::TunnelGatewayMetrics,
        packet_policy::{PacketPolicyError, inbound_datagram_check},
        state::SharedTunnelGatewayState,
    },
};

/// Tunnel gateway.
pub struct TunnelGateway<T>
where
    T: for<'de> Deserialize<'de> + Token,
{
    snap_tunnel_endpoint: Arc<snap_tun::server::Server<T>>,
    state: SharedTunnelGatewayState<T>,
    metrics: TunnelGatewayMetrics,
}

impl<T> Clone for TunnelGateway<T>
where
    T: for<'de> Deserialize<'de> + Token + Clone,
{
    fn clone(&self) -> Self {
        Self {
            snap_tunnel_endpoint: self.snap_tunnel_endpoint.clone(),
            state: self.state.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<T> TunnelGateway<T>
where
    T: for<'de> Deserialize<'de> + Token + Clone,
{
    /// Create new tunnel gateway instance.
    pub fn new(
        state: SharedTunnelGatewayState<T>,
        server: snap_tun::server::Server<T>,
        metrics: TunnelGatewayMetrics,
    ) -> Self {
        Self {
            snap_tunnel_endpoint: Arc::new(server),
            state,
            metrics,
        }
    }

    /// Starts the tunnel gateway server.
    ///
    /// The tunnel gateway accepts incoming QUIC connections and tries to establish SNAP tunnels on
    /// the accepted connections.
    #[instrument(name = "tunnel_gateway", skip_all)]
    pub async fn start_server<D: Dispatcher + 'static>(
        &self,
        cancellation_token: CancellationToken,
        endpoint: QuinnEndpoint,
        dispatcher: Arc<D>,
    ) -> std::io::Result<()> {
        while let Some(connection) = endpoint.accept().await {
            match connection.await {
                Ok(c) => {
                    tokio::spawn(
                        self.clone()
                            .handle_connection(
                                c,
                                cancellation_token.child_token(),
                                dispatcher.clone(),
                            )
                            .in_current_span(),
                    );
                }
                Err(e) => {
                    error!(error=%e, "Failed accepting new connection");
                }
            }
        }

        Err(std::io::Error::other(
            "Tunnel gateway server stopped unexpectedly",
        ))
    }

    #[instrument(skip_all, fields(remote_addr = %conn.remote_address()))]
    async fn handle_connection<D: Dispatcher + 'static>(
        self,
        conn: Connection,
        cancellation_token: CancellationToken,
        dispatcher: Arc<D>,
    ) {
        let local_addr =
            HostAddr::from(conn.local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));

        let (tx, rx, ctrl) = match self.snap_tunnel_endpoint.accept_with_timeout(conn).await {
            Ok(session) => session,
            Err(e) => {
                error!(error=%e, "Failed to accept snaptun tunnel");
                return;
            }
        };
        self.metrics.snaptun_connections_active.inc();

        // Spawn a task to handle the session control stream.
        tokio::spawn(async move {
            match ctrl.await {
                Ok(_) => {
                    debug!("Session control stream closed gracefully");
                }
                Err(e) => {
                    error!(error=%e, "Session control stream closed with error");
                }
            }
        });

        let assigned_addrs = tx.assigned_addresses();
        assert!(
            !assigned_addrs.is_empty(),
            "At least one address must be assigned"
        );
        let cloned_addrs: Vec<EndhostAddr> = assigned_addrs.clone();
        let shared_tx = Arc::new(tx);
        // Insert the tunnel for each assigned address into the tunnels map.
        {
            for &addr in assigned_addrs.iter() {
                self.state.add_tunnel(addr, shared_tx.clone());
                debug!(%addr, "Added new SNAP tunnel");
            }
        }

        cancellation_token
            .run_until_cancelled(async move {
                loop {
                    // Handle new datagram.
                    match rx.receive().await {
                        Ok(data) => {
                            match inbound_datagram_check(&data[..], &assigned_addrs) {
                                Ok(pkt) => {
                                    dispatcher.try_dispatch(pkt);
                                }
                                Err(e) => {
                                    debug!(err=%e, "inbound datagram check failed");
                                    // Use the first assigned address for the SCMP reply.
                                    Self::handle_scmp_error(
                                        e,
                                        data,
                                        local_addr,
                                        assigned_addrs[0],
                                        shared_tx.clone(),
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            match e {
                                snap_tun::server::ReceivePacketError::ConnectionClosed => {
                                    info!("Connection closed by client");
                                    break;
                                }
                                snap_tun::server::ReceivePacketError::ConnectionError(e) => {
                                    error!(error=%e, "Connection error");
                                    break;
                                }
                            }
                        }
                    }
                }
            })
            .await;

        // The session was closed by the client or cancelled by the server.
        for addr in cloned_addrs {
            self.state.remove_tunnel(addr);
            debug!(%addr, "Removed SNAP tunnel");
        }
        self.metrics.snaptun_connections_active.dec();
    }

    fn handle_scmp_error(
        err: PacketPolicyError,
        data: Bytes,
        local_addr: HostAddr,
        dst_addr: EndhostAddr,
        tx: Arc<snap_tun::server::Sender<T>>,
    ) {
        let scmp_message = match inbound_scmp_error(err, data) {
            Ok(s) => s,
            Err(e) => {
                error!(error=%e, "Error creating SCMP message");
                return;
            }
        };

        // Create AS-local empty path for SCMP packet
        let path = DataPlanePath::EmptyPath;

        let endpoint = ByEndpoint {
            source: ScionAddr::new(dst_addr.isd_asn(), local_addr),
            destination: dst_addr.into(),
        };

        let scmp_packet = match ScionPacketScmp::new(endpoint, path, scmp_message) {
            Ok(p) => p,
            Err(e) => {
                error!(error=%e, "Error creating SCMP packet");
                return;
            }
        };

        if let Err(e) = tx.send(scmp_packet.encode_to_bytes_vec().concat().into()) {
            info!(error=%e, "Error sending SCMP message");
        }
    }
}

fn inbound_scmp_error(err: PacketPolicyError, d: Bytes) -> Result<ScmpMessage, ScmpEncodeError> {
    let scmp_message = match err {
        PacketPolicyError::InvalidCommonHeader(_error) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidCommonHeader,
                0,
                d,
            ))
        }
        PacketPolicyError::InvalidAddressHeader(_error) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidAddressHeader,
                CommonHeader::LENGTH as u16,
                d,
            ))
        }
        // TODO(bunert): The pointer should point to the SrcHostAddr offset and not SrcISD.
        PacketPolicyError::InvalidSourceAddress => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidSourceAddress,
                (CommonHeader::LENGTH + (IsdAsn::BITS as usize) / 8) as u16,
                d,
            ))
        }
        PacketPolicyError::InvalidPathType(_type) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::UnknownPathType,
                CommonHeader::PATH_TYPE_OFFSET,
                d,
            ))
        }
        PacketPolicyError::InvalidPath(_error, offset) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidPath,
                offset,
                d,
            ))
        }
        PacketPolicyError::InconsistentPathLength(offset) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidPath,
                offset,
                d,
            ))
        }
        PacketPolicyError::PacketEmptyOrTruncated(offset) => {
            ScmpMessage::from(ScmpParameterProblem::new(
                ParameterProblemCode::InvalidPacketSize,
                offset,
                d,
            ))
        }
    };

    Ok(scmp_message)
}

/// Tunnel gateway error.
#[derive(Debug, thiserror::Error)]
pub enum TunnelGatewayError {
    /// I/O error.
    #[error("i/o error: {0:?}")]
    IoError(#[from] std::io::Error),
}
