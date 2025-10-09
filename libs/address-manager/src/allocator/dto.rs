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

use anyhow::Context;
use rand::SeedableRng;
use rand_chacha::{ChaCha8Core, ChaCha8Rng};
use scion_sdk_utils::rangeset::{Range, RangeSet};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::allocator::{AddrSet, AddressAllocator};

/// The address allocator.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AddressAllocatorDto {
    /// The list of IPv4 address sets.
    pub v4: Vec<AddrSetDto>,
    /// The list of IPv6 address sets.
    pub v6: Vec<AddrSetDto>,
    /// The random number generator state.
    pub rng: RngDto,
}

impl TryFrom<AddressAllocatorDto> for AddressAllocator {
    type Error = anyhow::Error;

    fn try_from(value: AddressAllocatorDto) -> Result<Self, Self::Error> {
        let rng = {
            let seet_bytes =
                hex::decode(value.rng.seed).context("seed is not a valid hex string")?;
            let mut rng = ChaCha8Rng::from(ChaCha8Core::from_seed(
                seet_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("seed with incorrect length"))?,
            ));
            rng.set_stream(value.rng.stream);
            rng.set_word_pos(value.rng.word);
            rng
        };

        let v4 = value
            .v4
            .into_iter()
            .map(AddrSet::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let v6 = value
            .v6
            .into_iter()
            .map(AddrSet::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { v4, v6, rng })
    }
}

impl From<&AddressAllocator> for AddressAllocatorDto {
    fn from(allocator: &AddressAllocator) -> Self {
        AddressAllocatorDto {
            v4: allocator.v4.iter().map(|s| s.into()).collect(),
            v6: allocator.v6.iter().map(|s| s.into()).collect(),
            rng: RngDto {
                seed: hex::encode(allocator.rng.get_seed()),
                word: allocator.rng.get_word_pos(),
                stream: allocator.rng.get_stream(),
            },
        }
    }
}

/// The random number generator state.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct RngDto {
    pub seed: String,
    pub word: u128,
    pub stream: u64,
}

/// An address set.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AddrSetDto {
    /// The prefix of the address set.
    pub prefix: String,
    /// The list of free addresses ranges.
    pub free: Vec<AddrRangeDto>,
}

impl TryFrom<AddrSetDto> for AddrSet {
    type Error = anyhow::Error;

    fn try_from(value: AddrSetDto) -> Result<Self, Self::Error> {
        Ok(Self {
            prefix: value.prefix.parse().context("invalid prefix")?,
            free: RangeSet::new(
                value
                    .free
                    .iter()
                    .map(|range| Range::new(range.start, range.end))
                    .collect(),
            )
            .context("invalid free address range set")?,
        })
    }
}

impl From<&AddrSet> for AddrSetDto {
    fn from(addr_set: &AddrSet) -> Self {
        AddrSetDto {
            prefix: addr_set.prefix.to_string(),
            free: addr_set
                .free
                .ranges()
                .iter()
                .map(|r| {
                    AddrRangeDto {
                        start: r.start,
                        end: r.end,
                    }
                })
                .collect(),
        }
    }
}

/// An address range.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct AddrRangeDto {
    /// The start of the address range.
    pub start: u128,
    /// The end of the address range.
    pub end: u128,
}
