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
//! SNAP data plane state.

use std::{collections::BTreeMap, fmt};

use address_manager::manager::AddressManager;
use anyhow::Context as _;
use scion_proto::address::IsdAsn;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::dto::DataPlaneStateDto;

/// The SNAP data plane state.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct DataPlaneState {
    /// The address registries (per ISD AS).
    pub address_registries: BTreeMap<IsdAsn, AddressManager>,
}

impl From<&DataPlaneState> for DataPlaneStateDto {
    fn from(value: &DataPlaneState) -> Self {
        DataPlaneStateDto {
            address_registries: value
                .address_registries
                .values()
                .map(|registry| registry.into())
                .collect(),
        }
    }
}

impl TryFrom<DataPlaneStateDto> for DataPlaneState {
    type Error = anyhow::Error;

    fn try_from(state: DataPlaneStateDto) -> Result<Self, Self::Error> {
        let registries = state
            .address_registries
            .into_iter()
            .map(|mngr| {
                let addr_mngr: AddressManager = mngr
                    .try_into()
                    .context("Failed to convert manager to AddressManager")?;
                Ok((addr_mngr.isd_asn(), addr_mngr))
            })
            .collect::<Result<BTreeMap<_, _>, Self::Error>>()?;

        Ok(Self {
            address_registries: registries,
        })
    }
}

/// Generic identifier trait.
pub trait Id {
    /// Creates an identifier from a `usize`.
    fn from_usize(val: usize) -> Self;
    /// Returns the identifier as a `usize`.
    fn as_usize(&self) -> usize;
}

/// Data plane identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ToSchema, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DataPlaneId(usize);

impl Id for DataPlaneId {
    fn as_usize(&self) -> usize {
        self.0
    }

    fn from_usize(val: usize) -> Self {
        Self(val)
    }
}

impl fmt::Display for DataPlaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
