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

//! Utils used internally in other modules.

/// This macro helps with creating enum types for some attributes that are encoded as short integer
/// values like [`u8`]. It generates bidirectional [`From`] implementations for the representation
/// type and supports catch-all/other variants.
macro_rules! encoded_type {
    (
        $(#[$outer:meta])*
        pub enum $name:ident ($representation_type:ty) {
            $($(#[$doc:meta])* $variant:ident = $value:literal),*;
            $($(#[$doc_other:meta])* $variant_other:ident = $range:pat,)*
        }
    ) => {
        $(#[$outer])*
        #[repr($representation_type)]
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$doc])* $variant = $value,)*
            $($(#[$doc_other])* $variant_other($representation_type),)*
        }

        impl From<$representation_type> for $name {
            fn from(value: $representation_type) -> Self {
                match value {
                    $($value => Self::$variant,)*
                    #[allow(clippy::redundant_pattern)]
                    $(x@$range => Self::$variant_other(x),)*
                }
            }
        }

        impl From<$name> for $representation_type {
            fn from(value: $name) -> Self {
                match value {
                    $($name::$variant => $value,)*
                    $($name::$variant_other(x) => x,)*
                }
            }
        }
    };
}
pub(crate) use encoded_type;
