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
//! Snap Segment Listing plan
//!
//! Snap requires more complex lookups, this module provides a plan for these

use anyhow::bail;
use scion_proto::address::{Asn, Isd, IsdAsn};

/// Plan of segment lookups to be performed for a request
#[derive(Debug)]
pub struct SnapListSegmentPlan {
    pub(crate) up: Option<(IsdAsn, IsdAsn)>,
    pub(crate) core: Option<(IsdAsn, IsdAsn)>,
    pub(crate) down: Option<(IsdAsn, IsdAsn)>,
}

impl SnapListSegmentPlan {
    /// Plans the lookups to be done on given Parameters
    pub fn new(src: Src, src_cores: CoreHint, dst: Dst) -> anyhow::Result<SnapListSegmentPlan> {
        if src.ias() == dst.ias() {
            bail!("Source and destination AS must differ in path segment lookup.");
        }
        let same_isd = src.isd() == dst.isd();
        match same_isd {
            true => Self::plan_same_isd(src, src_cores, dst),
            false => Self::plan_cross_isd(src, dst),
        }
    }

    fn plan_same_isd(
        src: Src,
        src_cores: CoreHint,
        dst: Dst,
    ) -> anyhow::Result<SnapListSegmentPlan> {
        let any_core = IsdAsn::new(src.isd(), Asn::WILDCARD);

        match src_cores {
            // Only a single core exists - we can optimize the lookup
            CoreHint::Single(single_core) => {
                match (src, dst) {
                    // Core to Core - No lookup since we know there are no routes
                    (Src::Core(_), Dst::Core(_)) | (Src::Core(_), Dst::AnyCore(_)) => Self::none(),

                    // Core to Down
                    (Src::Core(src), Dst::NonCore(dst)) => Self::down(src, dst),

                    // Non Core to Core
                    (Src::NonCore(src), Dst::Core(dst)) => Self::up(src, dst),
                    (Src::NonCore(src), Dst::AnyCore(dst)) => Self::up(src, dst),

                    // Non Core to Non Core
                    (Src::NonCore(src), Dst::NonCore(dst)) => Self::up_down(src, single_core, dst),
                }
            }
            // There are multiple cores in the ISD
            CoreHint::Multiple => {
                match (src, dst) {
                    // Core to Core
                    (Src::Core(src), Dst::Core(dst)) => Self::core(src, dst),
                    (Src::Core(src), Dst::AnyCore(dst)) => Self::core(src, dst),

                    // Core to Down
                    (Src::Core(src), Dst::NonCore(dst)) => Self::core_down(src, any_core, dst),

                    // Non Core to Core
                    (Src::NonCore(src), Dst::AnyCore(dst)) => Self::up(src, dst),
                    (Src::NonCore(src), Dst::Core(dst)) => Self::up_core(src, any_core, dst),

                    // Non Core to Non Core
                    (Src::NonCore(src), Dst::NonCore(dst)) => {
                        Self::up_core_down(src, any_core, any_core, dst)
                    }
                }
            }
        }
    }

    fn plan_cross_isd(src: Src, dst: Dst) -> Result<SnapListSegmentPlan, anyhow::Error> {
        let src_any_core = IsdAsn::new(src.isd(), Asn::WILDCARD);
        let dst_any_core = IsdAsn::new(dst.isd(), Asn::WILDCARD);

        match (src, dst) {
            // Core to Core
            (Src::Core(src), Dst::Core(dst)) => Self::core(src, dst),
            (Src::Core(src), Dst::AnyCore(dst)) => Self::core(src, dst),

            // Core to Down
            (Src::Core(src), Dst::NonCore(dst)) => Self::core_down(src, dst_any_core, dst),

            // Non Core to Core
            (Src::NonCore(src), Dst::AnyCore(dst)) => Self::up_core(src, src_any_core, dst),
            (Src::NonCore(src), Dst::Core(dst)) => Self::up_core(src, src_any_core, dst),

            // Non Core to Non Core
            (Src::NonCore(src), Dst::NonCore(dst)) => {
                Self::up_core_down(src, src_any_core, dst_any_core, dst)
            }
        }
    }
}

impl SnapListSegmentPlan {
    /// Checks if the Lookup could be satisfied
    fn validate(self) -> anyhow::Result<Self> {
        if self.up.is_none() && self.core.is_none() && self.down.is_none() {
            bail!("At least one segment lookup must be specified");
        }

        if let Some((src, dst)) = &self.up {
            if src.isd() != dst.isd() {
                bail!(
                    "Up segment lookup must be in same ISD: {} != {}",
                    src.isd(),
                    dst.isd()
                );
            }

            if src.is_wildcard() {
                bail!("Up segment lookup source must not be wildcard: {}", src);
            }
        }

        if let Some((src, dst)) = &self.down {
            if src.isd() != dst.isd() {
                bail!(
                    "Down segment lookup must be in same ISD: {} != {}",
                    src.isd(),
                    dst.isd()
                );
            }

            if dst.is_wildcard() {
                bail!(
                    "Down segment lookup destination must not be wildcard: {}",
                    src
                );
            }
        }

        Ok(self)
    }

    /// No-op segments lookup.
    pub fn none() -> anyhow::Result<SnapListSegmentPlan> {
        SnapListSegmentPlan {
            up: None,
            core: None,
            down: None,
        }
        .validate()
    }

    /// Core segments lookup.
    pub fn core(src: IsdAsn, dst: IsdAsn) -> anyhow::Result<SnapListSegmentPlan> {
        SnapListSegmentPlan {
            up: None,
            core: Some((src, dst)),
            down: None,
        }
        .validate()
    }

    /// Single Up Segments lookup.
    ///
    /// src and dst must be in same ISD
    pub fn up(src: IsdAsn, dst: IsdAsn) -> anyhow::Result<SnapListSegmentPlan> {
        SnapListSegmentPlan {
            up: Some((src, dst)),
            core: None,
            down: None,
        }
        .validate()
    }

    /// Single Down Segments lookup.
    ///
    /// src and dst must be in same ISD
    pub fn down(src: IsdAsn, dst: IsdAsn) -> anyhow::Result<SnapListSegmentPlan> {
        SnapListSegmentPlan {
            up: None,
            core: None,
            down: Some((src, dst)),
        }
        .validate()
    }

    /// Up segment lookup, followed by a core segment lookup
    ///
    /// src and transit must be in same ISD
    /// dst can only be a core
    pub fn up_core(
        src: IsdAsn,
        transit: IsdAsn,
        dst: IsdAsn,
    ) -> anyhow::Result<SnapListSegmentPlan> {
        SnapListSegmentPlan {
            up: Some((src, transit)),
            core: Some((transit, dst)),
            down: None,
        }
        .validate()
    }

    /// Core segment lookup, followed by a down segment lookup
    ///
    /// src must be a core AS
    /// transit and dst must be in same ISD
    pub fn core_down(
        src: IsdAsn,
        transit: IsdAsn,
        dst: IsdAsn,
    ) -> anyhow::Result<SnapListSegmentPlan> {
        SnapListSegmentPlan {
            up: None,
            core: Some((src, transit)),
            down: Some((transit, dst)),
        }
        .validate()
    }

    /// Up lookup followed by a down lookup
    ///
    /// src, dst and transit mut be in the same ISD
    pub fn up_down(
        src: IsdAsn,
        transit: IsdAsn,
        dst: IsdAsn,
    ) -> anyhow::Result<SnapListSegmentPlan> {
        SnapListSegmentPlan {
            up: Some((src, transit)),
            core: None,
            down: Some((transit, dst)),
        }
        .validate()
    }

    /// Up lookup followed by a down lookup
    ///
    /// src and src_transit must be in the same ISD
    /// dst_transit and dst must be in the same ISD
    pub fn up_core_down(
        src: IsdAsn,
        src_transit: IsdAsn,
        dst_transit: IsdAsn,
        dst: IsdAsn,
    ) -> anyhow::Result<SnapListSegmentPlan> {
        SnapListSegmentPlan {
            up: Some((src, src_transit)),
            core: Some((src_transit, dst_transit)),
            down: Some((dst_transit, dst)),
        }
        .validate()
    }
}

/// Destination AS Type for Segment Lookup
pub enum Dst {
    /// A Core AS
    Core(IsdAsn),
    /// A non-core AS
    NonCore(IsdAsn),
    /// Any Core AS in the ISD
    AnyCore(IsdAsn),
}

impl Dst {
    pub(crate) fn new(ias: IsdAsn, is_core: bool) -> Self {
        match ias.is_wildcard() {
            true => Dst::AnyCore(ias),
            false if is_core => Dst::Core(ias),
            false => Dst::NonCore(ias),
        }
    }

    pub(crate) fn ias(&self) -> IsdAsn {
        match self {
            Dst::Core(ias) => *ias,
            Dst::NonCore(ias) => *ias,
            Dst::AnyCore(isd) => IsdAsn::new(isd.isd(), Asn::WILDCARD),
        }
    }

    pub(crate) fn isd(&self) -> Isd {
        match self {
            Dst::Core(ias) => ias.isd(),
            Dst::NonCore(ias) => ias.isd(),
            Dst::AnyCore(ias) => ias.isd(),
        }
    }
}

/// Source AS Type for Segment Lookup
pub enum Src {
    /// A Core AS
    Core(IsdAsn),
    /// A non-core AS
    NonCore(IsdAsn),
}

impl Src {
    pub(crate) fn new(ias: IsdAsn, is_core: bool) -> anyhow::Result<Self> {
        match ias.is_wildcard() {
            true => bail!("Source AS must not be wildcard"),
            false if is_core => Ok(Src::Core(ias)),
            false => Ok(Src::NonCore(ias)),
        }
    }

    pub(crate) fn ias(&self) -> IsdAsn {
        match self {
            Src::Core(ias) => *ias,
            Src::NonCore(ias) => *ias,
        }
    }

    pub(crate) fn isd(&self) -> Isd {
        match self {
            Src::Core(ias) => ias.isd(),
            Src::NonCore(ias) => ias.isd(),
        }
    }
}

/// Hint on count of Core ASes in a ISD
pub enum CoreHint {
    /// Only a single Core can be used to route in this AS
    Single(IsdAsn),
    /// Multiple ASes exist to route in this ISD
    Multiple,
}
