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

use core::fmt;
use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::IpNet;
use scion_sdk_utils::rangeset::{Range, RangeSet};
use thiserror::Error;

/// A set of IP addresses.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AddrSet {
    pub(crate) prefix: IpNet,
    /// free stores the number of free addresses before the next allocated address.
    /// For example, if the prefix is 192.168.1.0/24, and the first 10 addresses are allocated,
    /// then free will be [10, 256].
    pub(crate) free: RangeSet<u128>,
}

impl Display for AddrSet {
    // Format the set as [from_address-to_address, from_address-to_address, ...]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.prefix.network() {
            IpAddr::V4(_) => {
                write!(f, "[")?;
                for range in self.free.ranges() {
                    write!(
                        f,
                        "{}-{}",
                        Ipv4Addr::from_bits(range.start as u32),
                        Ipv4Addr::from_bits(range.end as u32)
                    )?;
                }
                write!(f, "]")
            }
            IpAddr::V6(_) => {
                write!(f, "[")?;
                for range in self.free.ranges() {
                    write!(
                        f,
                        "{}-{}",
                        Ipv6Addr::from_bits(range.start),
                        Ipv6Addr::from_bits(range.end)
                    )?;
                }
                write!(f, "]")
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum AddrSetError {
    #[error("address {0} not in prefix")]
    AddressNotInPrefix(IpAddr),
    #[error("address {0} already exists")]
    AddressAlreadyInSet(IpAddr),
    #[error("address {0} does not exist")]
    AddressNotInSet(IpAddr),
    #[error("address has wrong IP version")]
    WrongIPVersion(IpAddr),
}

impl AddrSet {
    pub fn new(prefix: IpNet) -> Self {
        match prefix.network() {
            IpAddr::V4(addr) => {
                Self {
                    prefix,
                    free: RangeSet::new(vec![Range::new(
                        addr.to_ipv6_mapped().to_bits(),
                        addr.to_ipv6_mapped().to_bits()
                            + 2u128.pow((32 - prefix.prefix_len()).into()),
                    )])
                    .unwrap(),
                }
            }
            IpAddr::V6(addr) => {
                Self {
                    prefix,
                    free: RangeSet::new(vec![Range::new(
                        addr.to_bits(),
                        addr.to_bits() + 2u128.pow((128 - prefix.prefix_len()).into()),
                    )])
                    .unwrap(),
                }
            }
        }
    }

    pub fn capacity(&self) -> u128 {
        2u128.pow(self.prefix.prefix_len() as u32)
    }

    pub fn len(&self) -> u128 {
        self.free.len()
    }

    pub fn is_empty(&self) -> bool {
        self.free.is_empty()
    }

    pub fn insert(&mut self, address: IpAddr) -> Result<(), AddrSetError> {
        // Check if the address has the same IP version as the prefix.
        if std::mem::discriminant(&address) != std::mem::discriminant(&self.prefix.network()) {
            return Err(AddrSetError::WrongIPVersion(address));
        }

        if !self.prefix.contains(&address) {
            return Err(AddrSetError::AddressNotInPrefix(address));
        }
        let a = match address {
            IpAddr::V4(addr) => addr.to_ipv6_mapped().to_bits(),
            IpAddr::V6(addr) => addr.to_bits(),
        };

        self.free
            .insert(a)
            .map_err(|_| AddrSetError::AddressAlreadyInSet(address))
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        if std::mem::discriminant(&address) != std::mem::discriminant(&self.prefix.network()) {
            return false;
        }
        let a = match address {
            IpAddr::V4(addr) => addr.to_ipv6_mapped().to_bits(),
            IpAddr::V6(addr) => addr.to_bits(),
        };
        self.free.contains(a)
    }

    pub fn remove(&mut self, address: IpAddr) -> Result<(), AddrSetError> {
        // Check if the address has the same IP version as the prefix.
        if std::mem::discriminant(&address) != std::mem::discriminant(&self.prefix.network()) {
            return Err(AddrSetError::WrongIPVersion(address));
        }

        let a = match address {
            IpAddr::V4(addr) => addr.to_ipv6_mapped().to_bits(),
            IpAddr::V6(addr) => addr.to_bits(),
        };

        self.free
            .remove(a)
            .map_err(|_| AddrSetError::AddressNotInSet(address))
    }

    /// return the nth free address in the set.
    pub fn nth_free(&self, n: u128) -> Option<IpAddr> {
        let a = self.free.nth(n)?;
        Some(match self.prefix.network() {
            IpAddr::V4(_) => IpAddr::V4(Ipv6Addr::from_bits(a).to_ipv4_mapped().unwrap()),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from_bits(a)),
        })
    }
}
