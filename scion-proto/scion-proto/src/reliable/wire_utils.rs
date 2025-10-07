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

use crate::address::{HostType, ServiceAddr};

pub(super) const IPV4_OCTETS: usize = 4;
pub(super) const IPV6_OCTETS: usize = 16;
pub(super) const LAYER4_PORT_OCTETS: usize = 2;

pub(super) fn encoded_address_length(host_type: HostType) -> usize {
    match host_type {
        HostType::Svc => ServiceAddr::ENCODED_LENGTH,
        HostType::Ipv4 => IPV4_OCTETS,
        HostType::Ipv6 => IPV6_OCTETS,
        HostType::None => 0,
    }
}

pub(super) fn encoded_port_length(host_type: HostType) -> usize {
    match host_type {
        HostType::None | HostType::Svc => 0,
        HostType::Ipv4 | HostType::Ipv6 => LAYER4_PORT_OCTETS,
    }
}

pub(super) fn encoded_address_and_port_length(host_type: HostType) -> usize {
    encoded_address_length(host_type) + encoded_port_length(host_type)
}
