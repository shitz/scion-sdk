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
//! Data transfer objects (DTOs) for the SNAP data plane.

use address_manager::manager::dto::AddressManagerDto;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The SNAP data plane state.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct DataPlaneStateDto {
    /// The address registries (per ISD AS) of the data plane.
    pub address_registries: Vec<AddressManagerDto>,
}
