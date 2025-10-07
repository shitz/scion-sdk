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
//! Token source trait for the connect RPC client.

use async_trait::async_trait;

pub mod refresh;
pub mod static_token;

/// The error type for token sources.
pub type TokenSourceError = Box<dyn std::error::Error + Sync + Send>;

/// A source for authentication tokens.
#[async_trait]
pub trait TokenSource: Send + Sync + 'static {
    /// Gets a token, possibly refreshing it.
    async fn get_token(&self) -> Result<String, TokenSourceError>;

    /// Formats the token for use in an `Authorization` header.
    ///
    /// The default implementation formats the token as a Bearer token.
    /// Override this method if a different format is required.
    fn format_header(&self, token: String) -> String {
        format!("Bearer {token}")
    }
}
