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
//! Tunnel gateway state.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    ops::Deref,
    sync::{Arc, RwLock},
};

use scion_proto::address::EndhostAddr;
use serde::{Deserialize, Serialize};
use snap_tun::server::SnapTunToken;

pub mod dto;

/// Shared tunnel gateway state.
#[derive(Debug, Default, Clone)]
pub struct SharedTunnelGatewayState<T: SnapTunToken>(
    Arc<RwLock<BTreeMap<EndhostAddr, Arc<snap_tun::server::Sender<T>>>>>,
);

impl<T: SnapTunToken> SharedTunnelGatewayState<T> {
    /// Creates a new, empty tunnel gateway state.
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(BTreeMap::new())))
    }
}

impl<T: SnapTunToken> Deref for SharedTunnelGatewayState<T> {
    type Target = Arc<RwLock<BTreeMap<EndhostAddr, Arc<snap_tun::server::Sender<T>>>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: SnapTunToken> SharedTunnelGatewayState<T> {
    pub(crate) fn add_tunnel(&self, addr: EndhostAddr, tunnel: Arc<snap_tun::server::Sender<T>>) {
        let mut tunnels = self.write().expect("no fail");

        tracing::debug!(%addr, "Adding snaptun connection");
        tunnels.insert(addr, tunnel);
    }

    pub(crate) fn remove_tunnel(&self, addr: EndhostAddr) {
        let mut tunnels = self.write().expect("no fail");
        tracing::debug!(%addr, "Removing snaptun connection");
        tunnels.remove(&addr);
    }

    pub(crate) fn get_tunnel(&self, addr: EndhostAddr) -> Option<Arc<snap_tun::server::Sender<T>>> {
        let tunnels = self.read().expect("no fail");
        tunnels.get(&addr).cloned()
    }
}

/// Tunnel gateway I/O configuration.
#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct TunnelGatewayIoConfig {
    /// Optional socket address to listen on for incoming SNAP tunnel connections.
    pub listen_addr: Option<SocketAddr>,
}

impl TunnelGatewayIoConfig {
    /// Creates a new tunnel gateway I/O configuration with the given listen address.
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr: Some(listen_addr),
        }
    }
}
