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
//! This module contains an incomplete struct to read scionproto topo files.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::address::IsdAsn;

/// SCION topology.
#[derive(Deserialize)]
pub struct Topo {
    /// Map of ISD-AS to AS info.
    #[serde(rename = "ASes")]
    pub ases: HashMap<IsdAsn, AS>,
    /// List of SCION links.
    pub links: Vec<Link>,
}

impl Topo {
    /// default_testing returns the topology from default.topo.
    /// A simple topology that can be used for testing.
    pub fn default_testing() -> Self {
        let default_topo = include_str!("default.topo");
        serde_yaml_ng::from_str(default_topo).unwrap()
    }
}

/// One end of a SCION link.
pub struct LinkEnd {
    /// ISD-AS.
    pub ia: IsdAsn,
    /// Interface ID.
    pub ifid: u16,
    /// Optional bridge ID.
    pub bridge_id: Option<String>,
}

impl<'de> Deserialize<'de> for LinkEnd {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let (ia, ifid) = s
            .split_once('#')
            .ok_or(serde::de::Error::custom("invalid link end"))?;
        // For some links the isd-as has a bridge id suffix.
        let mut ia_split = ia.split("-");
        Ok(LinkEnd {
            // include the ia and ifid strings in the error message
            ia: IsdAsn::new(
                ia_split
                    .next()
                    .unwrap()
                    .parse()
                    .map_err(|_| serde::de::Error::custom(format!("invalid ia: {ia}")))?,
                ia_split
                    .next()
                    .unwrap()
                    .parse()
                    .map_err(|_| serde::de::Error::custom(format!("invalid ia: {ia}")))?,
            ),
            bridge_id: ia_split.next().map(|s| s.to_string()),
            ifid: ifid
                .parse()
                .map_err(|_| serde::de::Error::custom(format!("invalid ifid: {ifid}")))?,
        })
    }
}

/// SCION link information.
#[derive(Deserialize)]
pub struct Link {
    /// Start of the link.
    pub a: LinkEnd,
    /// End of the link.
    pub b: LinkEnd,
    /// Type of the link.
    #[serde(rename = "linkAtoB")]
    pub link_type: LinkType,
    /// Optional MTU for the link.
    pub mtu: Option<u32>,
    /// Optional underlay for the link.
    pub underlay: Option<Underlay>,
}

/// AS information.
#[derive(Deserialize)]
pub struct AS {
    /// Core AS.
    #[serde(default)]
    pub core: bool,
    /// Voting AS.
    #[serde(default)]
    pub voting: bool,
    /// Authoritative AS.
    #[serde(default)]
    pub authoritative: bool,
    /// Issuing AS.
    #[serde(default)]
    pub issuing: bool,
    /// Optional underlay.
    #[serde(default)]
    pub underlay: Option<Underlay>,
    /// Certificate issuer.
    pub cert_issuer: Option<String>,
    /// Optional MTU for the AS.
    pub mtu: Option<u32>,
}

/// Link type.
#[derive(Serialize, Deserialize)]
pub enum LinkType {
    /// Core link.
    #[serde(rename = "CORE")]
    Core,
    /// Child link.
    #[serde(rename = "CHILD")]
    Child,
    /// Peer link.
    #[serde(rename = "PEER")]
    Peer,
}

/// Underlay.
#[derive(Serialize, Deserialize)]
pub enum Underlay {
    /// UDP over IPv4
    #[serde(rename = "UDP/IPv4")]
    UdpIpv4,
    /// UDP over IPv6
    #[serde(rename = "UDP/IPv6")]
    UdpIpv6,
}
