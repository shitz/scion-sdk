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
//! Dispatchers sending packets into the [NetworkSimulator]

use scion_proto::{address::IsdAsn, packet::ScionPacketRaw};
use snap_dataplane::dispatcher::Dispatcher;

use crate::{
    network::{scion::routing::ScionNetworkTime, simulator::NetworkSimulator},
    state::SharedPocketScionState,
};

/// Dispatches packets into the [NetworkSimulator]
///
/// Bound to a specific AS
pub(crate) struct AsNetSimDispatcher {
    local_as: IsdAsn,
    app_state: SharedPocketScionState,
}

impl AsNetSimDispatcher {
    pub(crate) fn new(local_as: IsdAsn, app_state: SharedPocketScionState) -> Self {
        Self {
            local_as,
            app_state,
        }
    }
}

impl Dispatcher for AsNetSimDispatcher {
    fn try_dispatch(&self, packet: ScionPacketRaw) {
        let network_time = ScionNetworkTime::now();
        let state_guard = self.app_state.system_state.read().unwrap();

        NetworkSimulator::new(&state_guard.sim_receivers, state_guard.topology.as_ref()).dispatch(
            self.local_as,
            network_time,
            packet,
        );
    }
}

/// Dispatches packets into the [NetworkSimulator]
///
/// Uses the packet's source address to determine the AS
pub(crate) struct NetSimDispatcher {
    app_state: SharedPocketScionState,
}

impl NetSimDispatcher {
    pub(crate) fn new(app_state: SharedPocketScionState) -> Self {
        Self { app_state }
    }
}

impl Dispatcher for NetSimDispatcher {
    fn try_dispatch(&self, packet: ScionPacketRaw) {
        let network_time = ScionNetworkTime::now();
        let state_guard = self.app_state.system_state.read().unwrap();

        NetworkSimulator::new(&state_guard.sim_receivers, state_guard.topology.as_ref()).dispatch(
            packet.headers.address.ia.source,
            network_time,
            packet,
        );
    }
}
