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
//! # Address Manager
//!
//! Manage a pool of addresses.
//!
//! The [manager::AddressManager] allocates addresses and associates allocation
//! with an user identity. A successful allocation will result in a
//! [manager::AddressGrant] which has a limited lifetime.
//!
//! The state of the address pool (which address to allocate next) is managed by
//! [allocator::AddressAllocator].

pub mod allocator;
pub mod dto;
pub mod manager;
