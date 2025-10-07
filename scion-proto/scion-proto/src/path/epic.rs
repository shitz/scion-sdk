// Copyright 2025 Mysten Labs
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

//! Types required for the EPIC path type.

use bytes::Bytes;
use scion_protobuf::daemon::v1 as daemon_grpc;

/// Authenticators to compute EPIC hop validation fields (HVFs).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct EpicAuths {
    /// Key to compute the penultimate hop validation field.
    pub phvf: Bytes,
    /// Key to compute the last hop validation field.
    pub lhvf: Bytes,
}

impl From<daemon_grpc::EpicAuths> for EpicAuths {
    fn from(value: daemon_grpc::EpicAuths) -> Self {
        Self {
            phvf: value.auth_phvf.into(),
            lhvf: value.auth_lhvf.into(),
        }
    }
}
