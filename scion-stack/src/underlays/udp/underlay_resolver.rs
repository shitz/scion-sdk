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
//! UDP underlay resolver.

use std::{
    collections::{HashMap, HashSet},
    net,
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use arc_swap::ArcSwap;
use endhost_api_client::client::EndhostApiClient;
use scion_proto::address::IsdAsn;
use tokio::task::JoinHandle;
use tracing::error;

/// UDP underlay resolver.
pub struct UdpUnderlayResolver {
    state: Arc<PeriodicUnderlayNextHopResolverState>,
    task: Option<JoinHandle<()>>,
}

impl UdpUnderlayResolver {
    /// Creates a new UDP underlay resolver.
    pub fn new(
        api_client: Arc<dyn EndhostApiClient>,
        fetch_interval: Duration,
        initial_state: HashMap<(IsdAsn, u16), net::SocketAddr>,
    ) -> Self {
        let state = Arc::new(PeriodicUnderlayNextHopResolverState::new(
            api_client,
            fetch_interval,
            initial_state,
        ));
        Self {
            state: state.clone(),
            task: match fetch_interval {
                Duration::ZERO => None,
                _ => Some(tokio::spawn(state.run())),
            },
        }
    }
}

impl Drop for UdpUnderlayResolver {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl UdpUnderlayResolver {
    pub(crate) fn resolve(
        &self,
        isd_as: IsdAsn,
        interface_id: u16,
    ) -> Result<net::SocketAddr, UnderlayNextHopResolverError> {
        let next_hops = self.state.next_hops.load();
        next_hops
            .get(&(isd_as, interface_id))
            .ok_or(UnderlayNextHopResolverError::NotFound(isd_as, interface_id))
            .cloned()
    }

    pub(crate) fn isd_ases(&self) -> HashSet<IsdAsn> {
        self.state
            .next_hops
            .load()
            .keys()
            .map(|(isd_as, _)| *isd_as)
            .collect()
    }
}

pub(crate) struct PeriodicUnderlayNextHopResolverState {
    api_client: Arc<dyn EndhostApiClient>,
    next_hops: ArcSwap<HashMap<(IsdAsn, u16), net::SocketAddr>>,
    fetch_interval: Duration,
}

impl PeriodicUnderlayNextHopResolverState {
    pub fn new(
        api_client: Arc<dyn EndhostApiClient>,
        fetch_interval: Duration,
        initial_state: HashMap<(IsdAsn, u16), net::SocketAddr>,
    ) -> Self {
        Self {
            api_client,
            next_hops: ArcSwap::new(Arc::new(initial_state)),
            fetch_interval,
        }
    }

    async fn run(self: Arc<Self>) {
        loop {
            if let Err(e) = self.update_next_hops().await {
                error!("Error updating underlay next hop resolver: {:#}", e);
            }
            tokio::time::sleep(self.fetch_interval).await;
        }
    }

    async fn update_next_hops(&self) -> anyhow::Result<()> {
        let dataplanes = self
            .api_client
            .list_underlays(IsdAsn::WILDCARD)
            .await
            .context("error listing data planes")?;
        let mut next_hops = HashMap::new();
        for dp in dataplanes.udp_underlay {
            for i in dp.interfaces {
                next_hops.insert((dp.isd_as, i), dp.internal_interface);
            }
        }
        self.next_hops.store(Arc::new(next_hops));
        Ok(())
    }
}

/// Resolve underlay next hop errors.
#[derive(Debug, thiserror::Error)]
pub enum UnderlayNextHopResolverError {
    /// Next hop not found.
    #[error("next hop not found: {0}#{1}")]
    NotFound(IsdAsn, u16),
}
