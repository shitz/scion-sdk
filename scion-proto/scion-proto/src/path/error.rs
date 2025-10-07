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

//! Errors encountered when parsing SCION paths.

use std::fmt::Display;

#[non_exhaustive]
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Error kinds for data plane paths.
pub enum DataPlanePathErrorKind {
    InvalidSegmentLengths,
    InfoFieldOutOfRange,
    HopFieldOutOfRange,
}

impl Display for DataPlanePathErrorKind {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self {
            DataPlanePathErrorKind::InvalidSegmentLengths => {
                "the sequence of segment lengths are invalid"
            }
            DataPlanePathErrorKind::InfoFieldOutOfRange => {
                "the current info field index is too large"
            }
            DataPlanePathErrorKind::HopFieldOutOfRange => {
                "the current hop field index is outside the range of the current info field"
            }
        };
        fmt.write_str(description)
    }
}

/// An error which can be returned when parsing a SCION path with metadata.
#[derive(Eq, PartialEq, Clone, Debug, thiserror::Error)]
pub struct PathParseError(PathParseErrorKind);

#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathParseErrorKind {
    EmptyRaw,
    InvalidRaw,
    NoInterface,
    InvalidInterface,
    InvalidPathInterface,
    InvalidNumberOfInterfaces,
    InvalidExpiration,
    InvalidMtu,
}

impl Display for PathParseError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description = match self.0 {
            PathParseErrorKind::EmptyRaw => "Empty raw path",
            PathParseErrorKind::InvalidRaw => "Invalid raw path",
            PathParseErrorKind::NoInterface => "No underlay address for local border router",
            PathParseErrorKind::InvalidInterface => {
                "Invalid underlay address for local border router"
            }
            PathParseErrorKind::InvalidPathInterface => "Invalid SCION interface",
            PathParseErrorKind::InvalidNumberOfInterfaces => {
                "Path metadata contains zero or an odd number of interfaces"
            }
            PathParseErrorKind::InvalidExpiration => "Invalid expiration timestamp",
            PathParseErrorKind::InvalidMtu => "Invalid MTU",
        };

        fmt.write_str(description)
    }
}

impl From<PathParseErrorKind> for PathParseError {
    fn from(value: PathParseErrorKind) -> Self {
        Self(value)
    }
}
