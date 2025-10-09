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
//! SNAP tunnel metrics.

use prometheus::IntCounter;
use scion_sdk_observability::metrics::registry::MetricsRegistry;

/// SNAP tunnel metrics.
pub struct Metrics {
    /// Sender metrics.
    pub sender_metrics: SenderMetrics,
    /// Receiver metrics.
    pub receiver_metrics: ReceiverMetrics,
}

impl Metrics {
    /// Create new metrics instance with the given registry.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Metrics {
            sender_metrics: SenderMetrics::new(metrics_registry),
            receiver_metrics: ReceiverMetrics::new(metrics_registry),
        }
    }
}

/// SNAP tunnel sender metrics.
#[derive(Debug, Clone)]
pub struct SenderMetrics {
    /// Total number of datagrams sent by the sender.
    pub datagrams_sent_total: IntCounter,
}

impl SenderMetrics {
    /// Create new sender metrics instance with the given registry.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        SenderMetrics {
            datagrams_sent_total: metrics_registry.int_counter(
                "snaptun_datagrams_sent_total",
                "Total number of datagrams sent by the sender.",
            ),
        }
    }
}

/// SNAP tunnel receiver metrics.
#[derive(Debug, Clone)]
pub struct ReceiverMetrics {
    /// Total number of datagrams received by the receiver.
    pub datagrams_received_total: IntCounter,
}

impl ReceiverMetrics {
    /// New receiver metrics instance with the given registry.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        ReceiverMetrics {
            datagrams_received_total: metrics_registry.int_counter(
                "snaptun_datagrams_received_total",
                "Total number of datagrams received by the receiver.",
            ),
        }
    }
}
