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

/// The type of an inter-domain link based on the underlay connection.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
pub enum LinkType {
    /// Invalid link type.
    Invalid = -1,
    /// Unspecified.
    #[default]
    Unset = 0,
    /// Direct physical connection.
    Direct,
    /// Connection with local routing/switching.
    MultiHop,
    /// Connection overlaid over publicly routed Internet.
    OpenNet,
}

impl From<i32> for LinkType {
    fn from(value: i32) -> Self {
        match value {
            0 => Self::Unset,
            1 => Self::Direct,
            2 => Self::MultiHop,
            3 => Self::OpenNet,
            _ => Self::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_values() {
        for link_type in [
            LinkType::Invalid,
            LinkType::Unset,
            LinkType::Direct,
            LinkType::MultiHop,
            LinkType::OpenNet,
        ] {
            assert_eq!(link_type, LinkType::from(link_type as i32));
        }
    }
}
