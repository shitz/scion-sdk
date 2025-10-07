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
//! Connect RPC client for the SNAP control plane API.

use std::{net::SocketAddr, ops::Deref, sync::Arc};

use async_trait::async_trait;
use endhost_api_client::client::CrpcEndhostApiClient;
use reqwest_connect_rpc::{client::CrpcClientError, token_source::TokenSource};
use url::Url;

use crate::{
    crpc_api::api_service::{
        GET_SNAP_DATA_PLANE_SESSION_GRANT, RENEW_SNAP_DATA_PLANE_SESSION_GRANT, SERVICE_PATH,
        convert::SessionGrantError, model::SessionGrant,
    },
    protobuf::anapaya::snap::v1::api_service::{
        GetSnapDataPlaneSessionGrantRequest, GetSnapDataPlaneSessionGrantResponse,
        RenewSnapDataPlaneSessionGrantRequest, RenewSnapDataPlaneSessionGrantResponse,
    },
};

/// Re-export the endhost API client and the reqwest connect RPC cllient.
pub mod re_export {
    pub use endhost_api_client::client::{CrpcEndhostApiClient, EndhostApiClient};
    pub use reqwest_connect_rpc::{client::CrpcClientError, token_source::*};
}

/// SNAP control plane API trait.
#[async_trait]
pub trait ControlPlaneApi: Send + Sync {
    /// Creates SNAP data plane sessions for all data planes.
    async fn create_data_plane_sessions(&self) -> Result<Vec<SessionGrant>, CrpcClientError>;
    /// Renews a SNAP data plane session for the given address.
    async fn renew_data_plane_session(
        &self,
        addr: SocketAddr,
    ) -> Result<SessionGrant, CrpcClientError>;
}

/// Connect RPC client for the SNAP control plane API.
pub struct CrpcSnapControlClient {
    client: CrpcEndhostApiClient,
}

impl Deref for CrpcSnapControlClient {
    type Target = CrpcEndhostApiClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl CrpcSnapControlClient {
    /// Creates a new client with default settings
    pub fn new(base_url: &Url) -> anyhow::Result<Self> {
        let client = CrpcEndhostApiClient::new(base_url)?;
        Ok(Self { client })
    }

    /// Creates a new client with the provided `reqwest::Client`.
    pub fn new_with_client(base_url: &Url, client: reqwest::Client) -> anyhow::Result<Self> {
        Ok(Self {
            client: CrpcEndhostApiClient::new_with_client(base_url, client)?,
        })
    }

    /// Uses the provided token source for authentication.
    pub fn use_token_source(&mut self, token_source: Arc<dyn TokenSource>) -> &mut Self {
        self.client.use_token_source(token_source);
        self
    }
}

#[async_trait]
impl ControlPlaneApi for CrpcSnapControlClient {
    async fn create_data_plane_sessions(&self) -> Result<Vec<SessionGrant>, CrpcClientError> {
        self.client
            .unary_request::<GetSnapDataPlaneSessionGrantRequest, GetSnapDataPlaneSessionGrantResponse>(
                &format!("{SERVICE_PATH}{GET_SNAP_DATA_PLANE_SESSION_GRANT}"),
                GetSnapDataPlaneSessionGrantRequest::default(),
            )
            .await?
            .try_into()
            .map_err(
                |e: SessionGrantError| {
                    CrpcClientError::DecodeError {
                        context: "decoding session grants".into(),
                        source: e.into(),
                        body: None,
                    }
                },
            )
    }
    async fn renew_data_plane_session(
        &self,
        address: SocketAddr,
    ) -> Result<SessionGrant, CrpcClientError> {
        self.client
            .unary_request::<RenewSnapDataPlaneSessionGrantRequest, RenewSnapDataPlaneSessionGrantResponse>(
                &format!("{SERVICE_PATH}{RENEW_SNAP_DATA_PLANE_SESSION_GRANT}"),
                RenewSnapDataPlaneSessionGrantRequest{
                    address: address.to_string(),
                },
            )
            .await?
            .try_into()
            .map_err(
                |e: SessionGrantError| {
                    CrpcClientError::DecodeError {
                        context: "decoding renewed session grant".into(),
                        source: e.into(),
                        body: None,
                    }
                },
            )
    }
}
