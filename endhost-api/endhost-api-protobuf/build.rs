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
//! Build script to compile the protobuf definitions.

use std::io::Result;

fn main() -> Result<()> {
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config.out_dir("src/proto");

    let proto_files = [
        "./protobuf/endhost/v1/path.proto",
        "./protobuf/endhost/v1/underlays.proto",
    ];
    let proto_include_paths = ["./protobuf", "../../scion-proto/scion-protobuf"];

    config
        .extern_path(
            ".proto.control_plane.v1",
            "scion_protobuf::control_plane::v1",
        )
        .extern_path(
            ".proto.control_plane.experimental.v1",
            "scion_protobuf::control_plane::v1",
        )
        .extern_path(".proto.crypto.v1", "scion_protobuf::crypto::v1")
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&proto_files, &proto_include_paths)
        .expect("failed to compile proto files");

    Ok(())
}
