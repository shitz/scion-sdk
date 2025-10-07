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
//! Path policies.

use std::cmp::Ordering;

use scion_proto::path;

/// A path wrapper that is passed to the path policy when selecting a path.
/// In the future, this will be used to add additional information to the path.
#[derive(Debug, Clone)]
pub struct PolicyPath<'a> {
    path: &'a path::Path,
    from_registration: bool,
}

impl<'a> PolicyPath<'a> {
    /// Create a new policy path from a scion path
    pub fn new(path: &'a path::Path, from_registration: bool) -> Self {
        Self {
            path,
            from_registration,
        }
    }

    /// Returns true if this path came from registration rather than fetching
    pub fn is_from_registration(&self) -> bool {
        self.from_registration
    }

    /// Get the underlying scion path
    pub fn scion_path(&self) -> &'a path::Path {
        self.path
    }
}

impl<'a> From<&'a path::Path> for PolicyPath<'a> {
    fn from(path: &'a path::Path) -> Self {
        Self {
            path,
            from_registration: false,
        }
    }
}

/// Path policy trait.
pub trait PathPolicy {
    /// Returns true if the path should be considered for selection.
    fn predicate(&self, path: &PolicyPath<'_>) -> bool;
    /// Indicates which of two paths is preferred, greater values are preferred.
    fn rank(&self, path1: &PolicyPath<'_>, path2: &PolicyPath<'_>) -> Ordering;
}

/// Selects the shortest path based on the number of hops.
#[derive(Default)]
pub struct Shortest {}

impl PathPolicy for Shortest {
    fn predicate(&self, _: &PolicyPath<'_>) -> bool {
        true
    }

    fn rank(&self, a: &PolicyPath<'_>, b: &PolicyPath<'_>) -> Ordering {
        // Prefer shorter paths and paths that come from registration.
        (a.path.interface_count(), a.is_from_registration())
            .cmp(&(b.path.interface_count(), b.is_from_registration()))
    }
}
