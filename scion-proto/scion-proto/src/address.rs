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

//! SCION addresses for ISDs, ASes, hosts, and sockets.
//!
//! This module provides end-host networking addresses for the SCION Internet architecture.
//!
//! # Organisation
//!
//! - An [`IsdAsn`] globally identifies an AS within the SCION network, and consists of an ISD
//!   identifier ([`Isd`]) and AS number ([`Asn`]).
//! - A [`HostAddr`] represents an AS-specific host addresses of either a IPv4, IPv6, or Service
//!   host; [`std::net::Ipv4Addr`], [`std::net::Ipv6Addr`], and [`ServiceAddr`] are their respective
//!   addresses.
//! - The above combined are a [`ScionAddr`], which is the globally-routeable address of IPv4, IPv6,
//!   or Service hosts in the SCION network; [`SocketAddrV4`], [`SocketAddrV6`], and
//!   [`ScionAddrSvc`] are the respective addresses.
//! - [`SocketAddr`] is a [`ScionAddr`] with an associated port, and is used for UDP application
//!   addressing; the respective IPv4, IPv6, and service types are [`SocketAddrV4`],
//!   [`SocketAddrV6`], and [`SocketAddrSvc`].

mod asn;
pub use asn::Asn;

mod isd;
pub use isd::Isd;

mod ia;
pub use ia::IsdAsn;

mod service;
pub use service::ServiceAddr;

mod host;
pub use host::{HostAddr, HostType};

mod socket_address;
pub use socket_address::{SocketAddr, SocketAddrSvc, SocketAddrV4, SocketAddrV6};

mod scion_address;
pub use scion_address::{ScionAddr, ScionAddrSvc, ScionAddrV4, ScionAddrV6};

mod endhost_address;
pub use endhost_address::{EndhostAddr, EndhostAddrError};

mod error;
pub use error::{AddressKind, AddressParseError};
