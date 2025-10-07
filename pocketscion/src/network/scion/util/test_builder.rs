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
//! Utility for constructing deterministic tests for SCION packets
//!
//! The [`TestBuilder`] defines:
//! - the exact sequence and state of hops a packet takes
//! - a consistent [`ScionTopology`] so packets remain valid in a simulated network.
//!
//!  #### To create a basic path
//! ```ignore
//! let segment_creation_timestamp = Utc::now().timestamp() as u32;
//! let routing_timestamp = segment_creation_timestamp + 1000;
//! let src_address = EndhostAddr::from_str("1-1,2.2.2.2").unwrap();
//! let dst_address = EndhostAddr::from_str("1-10,4.4.4.4").unwrap();
//!
//! let context: TestContext = TestBuilder::new()
//!     .using_info_timestamp(segment_creation_timestamp)
//!     .up()
//!     .add_hop(0, 1)
//!     .add_hop(1, 0)
//!     .build(src_address, dst_address, routing_timestamp);
//! ```
//!
//! ----
//!
//! #### Building a Topology from the Context
//!
//! Easiest way to work with the [`TestBuilder`] is to use a topology built from it.
//!
//! ```ignore
//! let ctx_topology = context.build_topology();
//! println!("{}", ctx_topology.format_mermaid());
//! ```
//!
//! The packets created by the TestContext will be valid on this topology.
//!
//! You can use [`ScionTopology::format_mermaid`] to visualize it.
//!
//! If you want to use an existing Topology, you will have to make sure that you are:
//! - using valid interface indexes in the hop fields
//! - using the correct Forwarding Keys for each hop
//! ----
//!
//! #### Creating SCION Packets
//!
//! ```ignore
//! let mut scion_raw = context.scion_packet_raw(b"example");
//! let scion_scmp =
//!     context.scion_packet_scmp(ScmpEchoRequest::new(1, 1, b"example".to_vec().into()).into());
//! let scion_udp = context.scion_packet_udp(b"example", 54000, 8080);
//! ```
//! ----
//!
//! #### Using the Test Context
//!
//! The test context can be directly used with any type taking a Topology and a Packet
//! ```ignore
//! let result = TopologyNetworkSim::simulate_traversal::<SpecRoutingLogic>(
//!     &ctx_topology,
//!     &mut scion_raw,
//!     ScionNetworkTime(context.timestamp),
//!     context.src_address.isd_asn(),
//! )
//! ```
//!
//! ----
//!
//! #### More Complex Paths
//! ```ignore
//! let context: TestContext = TestBuilder::new()
//!     .down() // Following hops are part of a down segment
//!     .add_hop(0, 2) // Normal entry hop, egress through interface 2
//!     .add_hop_with_egress_down(3, 4) // This hop will have egress interface down
//!     .add_hop_with_alerts(2, true, 0, false) // This hop has SCMP alert on ingress
//!     .core() // Following hops are part of a core segment
//!     .using_forwarding_key([2; 16].into()) // Following hops use this key
//!     .add_hop(0, 1) // Normal core hop
//!     .add_hop(1, 0) // Core hop to local
//!     .build_with_path_modifier(src_address, dst_address, routing_timestamp, |mut path| {
//!         // Allow any modifications to the path
//!         path.hop_fields[1].mac = [0u8; 6]; // E.g. Tamper with the hop mac to simulate a fault
//!         path
//!     });
//! ```
//!
//! ----
//!
//! #### More Complex Use Cases
//!
//! [`TestContext`] exposes the [`TestBuilderSegment`] it used to build the Path
//!
//! You can use these to build wrappers around the TestContext for specialized use cases. \
//! See [`crate::network::scion::routing::spec::SpecRoutingLogic`] tests for an example of one
//! such wrapper.

use scion_proto::{
    address::{Asn, EndhostAddr, Isd, IsdAsn, SocketAddr},
    packet::{ByEndpoint, FlowId, ScionPacketRaw, ScionPacketScmp, ScionPacketUdp},
    path::{DataPlanePath, HopField, InfoField, SegmentLength, StandardPath},
    scmp::ScmpMessage,
};

use crate::network::scion::{
    crypto::{ForwardingKey, calculate_hop_mac, mac_chaining_step, validate_segment_macs},
    routing::AsRoutingLinkType,
    topology::{ScionAs, ScionLink, ScionLinkType, ScionTopology},
};

/// A builder for constructing deterministic SCION Path tests.
///
/// The `TestBuilder` lets you define the exact hop sequence a packet
/// will traverse in a simulated SCION network.
///
/// It produces a [`TestContext`] which supplies valid packets and a consistent [`ScionTopology`].
///
/// This is intended for tests only, not for constructing production paths.
#[derive(Debug, Default)]
pub struct TestBuilder {
    segments: Vec<TestBuilderSegment>,
    default_timestamp: u32,
    default_hop_expiry: u8,
    default_key: ForwardingKey,
}
impl TestBuilder {
    #[allow(unused)]
    pub(crate) fn new() -> Self {
        TestBuilder {
            default_timestamp: 0,
            default_hop_expiry: 255,
            ..Default::default()
        }
    }

    #[allow(unused)]
    pub(crate) fn using_info_timestamp(mut self, timestamp: u32) -> Self {
        self.default_timestamp = timestamp;
        self
    }

    #[allow(unused)]
    pub(crate) fn with_hop_expiry(mut self, exp_time: u8) -> Self {
        self.default_hop_expiry = exp_time;
        self
    }

    #[allow(unused)]
    pub(crate) fn using_forwarding_key(mut self, key: ForwardingKey) -> Self {
        self.default_key = key;
        self
    }

    #[allow(unused)]
    pub(crate) fn down(mut self) -> Self {
        self.add_segment(true, self.default_timestamp, AsRoutingLinkType::LinkToChild);
        self
    }

    #[allow(unused)]
    pub(crate) fn core(mut self) -> Self {
        self.add_segment(true, self.default_timestamp, AsRoutingLinkType::LinkToCore);
        self
    }

    #[allow(unused)]
    pub(crate) fn up(mut self) -> Self {
        self.add_segment(
            false,
            self.default_timestamp,
            AsRoutingLinkType::LinkToParent,
        );
        self
    }

    #[allow(unused)]
    pub(crate) fn add_hop(self, ingress_if: u16, egress_if: u16) -> Self {
        self.add_hop_internal(ingress_if, false, egress_if, false, false)
    }

    #[allow(unused)]
    pub(crate) fn add_hop_with_egress_down(self, ingress_if: u16, egress_if: u16) -> Self {
        self.add_hop_internal(ingress_if, false, egress_if, false, true)
    }

    #[allow(unused)]
    pub(crate) fn add_hop_with_alerts(
        self,
        ingress_if: u16,
        ingress_alert: bool,
        egress_if: u16,
        egress_alert: bool,
    ) -> Self {
        self.add_hop_internal(ingress_if, ingress_alert, egress_if, egress_alert, false)
    }

    fn add_hop_internal(
        mut self,
        ingress_if: u16,
        ingress_alert: bool,
        egress_if: u16,
        egress_alert: bool,
        egress_down: bool,
    ) -> Self {
        let current_segment = self
            .segments
            .last_mut()
            .expect("Path must have at least one segment");
        let cons_dir = current_segment.info_field.cons_dir;

        let (ingress_link_type, egress_link_type) = match (ingress_if, egress_if) {
            (0, 0) => (None, None),                                        // Local
            (0, _) => (None, Some(current_segment.uplink_type)),           // Local to egress
            (_, 0) => (Some(current_segment.uplink_type.reverse()), None), /* Ingress to local */
            (..) => {
                (
                    Some(current_segment.uplink_type.reverse()),
                    Some(current_segment.uplink_type),
                )
            }
        };

        current_segment.hop_fields.push(TestBuilderHopField {
            cons_dir,
            ingress_link_type,
            ingress_if,
            egress_if,
            egress_link_type,
            egress_interface_down: egress_down,
            ingress_router_alert: ingress_alert,
            egress_router_alert: egress_alert,
            exp_time: self.default_hop_expiry,
            segment_change_next: false,
            forwarding_key: self.default_key,
        });

        self
    }

    #[allow(unused)]
    pub(crate) fn build(
        self,
        src_address: EndhostAddr,
        dst_address: EndhostAddr,
        routing_timestamp: u32,
    ) -> TestContext {
        self.build_with_path_modifier(src_address, dst_address, routing_timestamp, |p| p)
    }

    /// Creates a test context
    ///
    /// Contains a valid SCION packet derived from the segments defined in the builder.
    ///
    /// `routing_timestamp` is the timestamp of when the packet is received
    pub fn build_with_path_modifier(
        self,
        src_address: EndhostAddr,
        dst_address: EndhostAddr,
        routing_timestamp: u32,
        path_modifier: impl FnOnce(StandardPath) -> StandardPath,
    ) -> TestContext {
        let mut segment_lengths: [SegmentLength; 3] = [SegmentLength::new_unchecked(0); 3];
        self.segments.iter().enumerate().for_each(|(i, segment)| {
            segment_lengths[i] = SegmentLength::new(segment.hop_fields.len() as u8)
                .expect("Segment length must be less than 64");
        });

        let path = match self.segments.is_empty() {
            true => DataPlanePath::EmptyPath,
            false => {
                let mut segment_hops = Vec::new();
                let mut segments_seg_ids = Vec::new();

                // Calculate MACs and build the hops
                for segment in &self.segments {
                    let mut previous_accumulator = segment.info_field.seg_id;
                    let mut accumulator = segment.info_field.seg_id;

                    // Calculating the macs has to happen in order of construction
                    let const_dir_iter: Box<dyn DoubleEndedIterator<Item = &TestBuilderHopField>> =
                        match segment.info_field.cons_dir {
                            true => Box::new(segment.hop_fields.iter()),
                            false => Box::new(segment.hop_fields.iter().rev()),
                        };

                    // Calculate the MACs
                    let mut hops = const_dir_iter
                        .cloned()
                        .map(|hop_definition| {
                            let forwarding_key = hop_definition.forwarding_key;
                            let hop = hop_definition
                                .into_hop_field(accumulator, segment.info_field.timestamp_epoch);

                            previous_accumulator = accumulator;
                            accumulator = mac_chaining_step(accumulator, hop.mac);

                            (hop, forwarding_key)
                        })
                        .collect::<Vec<_>>();

                    // Sanity - Validate macs
                    validate_segment_macs(&segment.info_field, &hops, segment.info_field.cons_dir)
                        .expect("MAC validation failed");

                    if segment.info_field.cons_dir {
                        segments_seg_ids.push(segment.info_field.seg_id);
                    } else {
                        // Reverse the hops
                        hops.reverse();
                        segments_seg_ids.push(previous_accumulator);
                    }

                    segment_hops.extend(hops.into_iter().map(|(hop, _)| hop));
                }

                let path = path_modifier(StandardPath {
                    path_meta: scion_proto::path::MetaHeader {
                        current_info_field: 0.into(),
                        current_hop_field: 0.into(),
                        reserved: 0.into(),
                        segment_lengths,
                    },
                    info_fields: self
                        .segments
                        .iter()
                        .zip(segments_seg_ids)
                        .map(|(seg, seg_id)| {
                            InfoField {
                                seg_id,
                                cons_dir: seg.info_field.cons_dir,
                                timestamp_epoch: seg.info_field.timestamp_epoch,
                                peer: seg.info_field.peer,
                            }
                        })
                        .collect(),
                    hop_fields: segment_hops,
                });

                DataPlanePath::Standard(path.into())
            }
        };

        TestContext {
            path,
            timestamp: routing_timestamp,
            test_segments: self.segments,
            dst_address,
            src_address,
        }
    }

    fn add_segment(
        &mut self,
        is_construction_dir: bool,
        timestamp: u32,
        uplink_type: AsRoutingLinkType,
    ) {
        if self.segments.len() >= 3 {
            panic!("Path can not have more than 3 segments");
        }
        let info_field = InfoField {
            cons_dir: is_construction_dir,
            timestamp_epoch: timestamp,
            seg_id: 0,
            peer: false,
        };

        if let Some(last) = self.segments.iter_mut().last() {
            last.hop_fields
                .iter_mut()
                .last()
                .expect("Last segment must have at least one hop")
                .segment_change_next = true;
        }

        self.segments.push(TestBuilderSegment {
            hop_fields: Vec::new(),
            info_field,
            uplink_type,
        });
    }
}

/// Test Context providing a SCION Packet and relevant per hop information
pub struct TestContext {
    pub(crate) path: DataPlanePath,
    #[allow(unused)]
    pub(crate) timestamp: u32,

    /// Defines the segments used to build the packet
    pub(crate) test_segments: Vec<TestBuilderSegment>,

    pub(crate) src_address: EndhostAddr,
    pub(crate) dst_address: EndhostAddr,
}

impl TestContext {
    /// Creates a raw SCION packet with the given payload
    ///
    /// The packet will use the path and addresses defined in the builder
    pub fn scion_packet_raw(&self, payload: &[u8]) -> ScionPacketRaw {
        ScionPacketRaw::new(
            ByEndpoint {
                source: self.src_address.into(),
                destination: self.dst_address.into(),
            },
            self.path.clone(),
            payload.to_owned().into(),
            0,
            FlowId::default(),
        )
        .expect("Failed to create SCION packet")
    }

    /// Creates a udp SCION packet with the given payload
    ///
    /// The packet will use the path and addresses defined in the builder
    pub fn scion_packet_udp(&self, payload: &[u8], src_port: u16, dst_port: u16) -> ScionPacketUdp {
        ScionPacketUdp::new(
            ByEndpoint {
                source: SocketAddr::new(self.src_address.into(), src_port),
                destination: SocketAddr::new(self.dst_address.into(), dst_port),
            },
            self.path.clone(),
            payload.to_owned().into(),
        )
        .expect("Failed to create SCION UDP packet")
    }

    /// Creates a scmp SCION packet with the given payload
    ///
    /// The packet will use the path and addresses defined in the builder
    pub fn scion_packet_scmp(&self, message: ScmpMessage) -> ScionPacketScmp {
        ScionPacketScmp::new(
            ByEndpoint {
                source: self.src_address.into(),
                destination: self.dst_address.into(),
            },
            self.path.clone(),
            message,
        )
        .expect("Failed to create SCION SCMP packet")
    }

    /// Builds a simple test topology where the packet in this context is valid
    ///
    /// If SRC and DST are in different ISDs, a Core Segment with at least 3 hops is required.
    ///
    /// Function will inject at least one Core AS to the topology.
    pub fn build_topology(&self) -> ScionTopology {
        let mut topology = ScionTopology::new();

        let src_as = self.src_address.isd_asn();
        let dst_as = self.dst_address.isd_asn();

        let mut using_isd = src_as.isd().to_u16();
        let mut as_counter = src_as.asn().to_u64();

        let mut previous_egress: Option<(IsdAsn, u16, bool)> = None;

        let mut after_segment_change = false;
        let mut has_changed_isd = false;

        // Determine the final hop
        let Some(final_hop) = self.test_segments.iter().flat_map(|s| &s.hop_fields).last() else {
            assert_eq!(
                src_as, dst_as,
                "If path is empty, src and dst AS must be the same"
            );

            let other_as = IsdAsn::new(Isd::new(using_isd), Asn::new(as_counter + 1));
            // If the path is empty, we just create a basic topolo`gy with two ASes
            topology
                .add_as(ScionAs::new_core(src_as))
                .unwrap()
                .add_as(ScionAs::new_core(other_as))
                .unwrap()
                .add_link(ScionLink::new(src_as, 1, ScionLinkType::Core, other_as, 1).unwrap())
                .unwrap();

            return topology;
        };

        for (seg_idx, segment) in self.test_segments.iter().enumerate() {
            for hop in &segment.hop_fields {
                if after_segment_change {
                    // If we switched to core segment - check if we need to change ISD
                    if hop.egress_link_type == Some(AsRoutingLinkType::LinkToCore)
                        && dst_as.isd() != src_as.isd()
                    {
                        assert!(
                            segment.hop_fields.len() >= 3,
                            "Need at least three core hops to change ISDs"
                        );
                        using_isd = dst_as.isd().to_u16();
                        has_changed_isd = true;
                    }

                    // update previous egress interface
                    let (isd, ..) = previous_egress
                        .take()
                        .expect("Previous egress should be set");

                    previous_egress = Some((isd, hop.egress_if, hop.egress_interface_down));

                    after_segment_change = false;
                    continue;
                }

                after_segment_change = hop.segment_change_next;

                // Get the next ASN
                let curr_as = if std::ptr::eq(hop, final_hop) {
                    dst_as // use our dst AS at the final hop
                } else {
                    // Count up from src AS
                    let mut next = IsdAsn::new(Isd::new(using_isd), Asn::new(as_counter));

                    // Avoid overlap with destination AS
                    if next == dst_as {
                        as_counter += 1;
                        next = IsdAsn::new(Isd::new(using_isd), Asn::new(as_counter));
                    }

                    as_counter += 1;
                    next
                };

                // Create a new AS for each hop
                let scion_as = match segment.uplink_type {
                    AsRoutingLinkType::LinkToCore => ScionAs::new_core(curr_as),
                    _ => {
                        // If this is a segment change, we need to see if the next AS might need to
                        // be a core
                        match hop.segment_change_next {
                            false => ScionAs::new(curr_as),
                            true => {
                                let next_segment = self
                                    .test_segments
                                    .get(seg_idx + 1)
                                    .expect("Next segment should exist on segment change");

                                if next_segment.uplink_type == AsRoutingLinkType::LinkToCore {
                                    ScionAs::new_core(curr_as)
                                } else {
                                    ScionAs::new(curr_as)
                                }
                            }
                        }
                    }
                };

                topology
                    .add_as(scion_as.with_forwarding_key(hop.forwarding_key.into()))
                    .expect("Should not fail to add AS");

                // Update previous AS
                let prev_as =
                    previous_egress.replace((curr_as, hop.egress_if, hop.egress_interface_down));
                let Some((prev_as, prev_egress, link_down)) = prev_as else {
                    // If this is the first hop no need to create a link
                    continue;
                };

                // Create a link between the previous AS and the current AS
                let link_type = match hop.ingress_link_type {
                    Some(link_type) => {
                        match link_type {
                            AsRoutingLinkType::LinkToCore => ScionLinkType::Core,
                            AsRoutingLinkType::LinkToParent => ScionLinkType::Parent,
                            AsRoutingLinkType::LinkToChild => ScionLinkType::Child,
                            AsRoutingLinkType::LinkToPeer => ScionLinkType::Peer,
                        }
                    }
                    None => continue, // Segment change
                };

                let mut link =
                    ScionLink::new(prev_as, prev_egress, link_type, curr_as, hop.ingress_if)
                        .expect("Should not fail to create links");

                link.set_is_up(!link_down);

                topology
                    .add_link(link)
                    .expect("Should not fail to add link");
            }
        }

        // Check if we have done a required ISD change
        if dst_as.isd() != src_as.isd() && !has_changed_isd {
            panic!(
                "If dst_ia is set, and ISD is not the same as start, the path must have at least one core segment with 3 hops to change ISD"
            );
        }

        // If there is no core AS, add one
        if !topology.as_map.values().any(|as_entry| as_entry.core) {
            let core_ia = IsdAsn::new(
                Isd::new(using_isd),
                Asn::new(as_counter.saturating_add(100)),
            ); // Could collide with another AS, not worth to worry about

            let core_as = ScionAs::new_core(core_ia);
            topology.add_as(core_as).expect("Failed to add core AS");

            // Add links from both src and dst AS to the core AS
            // Will make sure there are no orphans along the way
            let src_link = ScionLink::new(src_as, 50, ScionLinkType::Child, core_ia, 50)
                .expect("Failed to create link");
            let dst_link = ScionLink::new(dst_as, 51, ScionLinkType::Child, core_ia, 51)
                .expect("Failed to create link");
            topology.add_link(src_link).expect("Failed to add link");
            topology.add_link(dst_link).expect("Failed to add link");
        }

        topology
    }
}

/// General Definition of a Hop Field
///
/// Together with [TestBuilderSegment], this contains all relevant information to build a [HopField]
///
/// For fields which mirror hop fields, see [HopField] for documentation
#[derive(Debug, Clone)]
pub struct TestBuilderHopField {
    /// If the Hop field is defined in Construction direction
    /// ingress/egress in this struct are travel direction
    pub(crate) cons_dir: bool,

    pub(crate) ingress_if: u16,
    /// The link type to the ingress interface (None = Local)
    /// If e.g. LinkToParent, we are the Parent
    pub(crate) ingress_link_type: Option<AsRoutingLinkType>,
    pub(crate) ingress_router_alert: bool,

    pub(crate) egress_if: u16,
    /// The link type from the egress interface (None = Local)
    /// If e.g. LinkToParent, we are the Child
    pub(crate) egress_link_type: Option<AsRoutingLinkType>,
    pub(crate) egress_router_alert: bool,

    /// If true, the egress interface of this Hop will be down
    pub(crate) egress_interface_down: bool,

    pub(crate) exp_time: u8,

    /// Forwarding key to use to authenticate this packet
    pub(crate) forwarding_key: ForwardingKey,

    /// If after this Hop there will be a segment change
    pub(crate) segment_change_next: bool,
}
impl TestBuilderHopField {
    fn into_hop_field(self, mac_beta: u16, timestamp: u32) -> HopField {
        let (cons_ingress, cons_egress) = match self.cons_dir {
            true => (self.ingress_if, self.egress_if),
            false => (self.egress_if, self.ingress_if),
        };

        let (ingress_router_alert, egress_router_alert) = match self.cons_dir {
            true => (self.ingress_router_alert, self.egress_router_alert),
            false => (self.egress_router_alert, self.ingress_router_alert),
        };

        HopField {
            cons_ingress,
            cons_egress,
            ingress_router_alert,
            egress_router_alert,
            exp_time: self.exp_time,
            mac: calculate_hop_mac(
                mac_beta,
                timestamp,
                self.exp_time,
                cons_ingress,
                cons_egress,
                &self.forwarding_key,
            ),
        }
    }
}

/// General Definition of Segments
///
/// Contains all relevant information to build a PathSegment
#[derive(Debug)]
pub struct TestBuilderSegment {
    pub(crate) info_field: InfoField,
    pub(crate) hop_fields: Vec<TestBuilderHopField>,
    // Link type all egress interfaces have in this segment
    pub(crate) uplink_type: AsRoutingLinkType,
}
