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

use scion_protobuf::daemon::v1 as daemon_grpc;

/// Geographic coordinates with latitude and longitude.
// Using a custom type to prevent importing a library here
#[derive(PartialEq, Clone, Debug, Default)]
pub struct GeoCoordinates {
    /// Latitude component of the coordinates.
    pub lat: f32,
    /// Longitude component of the coordinates.
    pub long: f32,
    /// The textual address corresponding to the coordinates.
    pub address: String,
}

impl From<daemon_grpc::GeoCoordinates> for GeoCoordinates {
    fn from(value: daemon_grpc::GeoCoordinates) -> Self {
        Self {
            lat: value.latitude,
            long: value.longitude,
            address: value.address,
        }
    }
}

impl GeoCoordinates {
    pub(crate) fn from_grpc_or_none(value: daemon_grpc::GeoCoordinates) -> Option<Self> {
        Some(value.into()).filter(|g| g != &GeoCoordinates::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_value() {
        assert_eq!(
            GeoCoordinates::default(),
            daemon_grpc::GeoCoordinates::default().into()
        );
    }
}
