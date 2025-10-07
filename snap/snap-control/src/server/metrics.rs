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
//! SNAP control plane API Prometheus middleware.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::body::Body;
use http::{Request, Response};
use observability::metrics::registry::MetricsRegistry;
use prometheus::{HistogramVec, IntCounterVec};
use tower::{BoxError, Layer, Service};

/// Prometheus middleware layer for tracking control plane API metrics.
#[derive(Clone)]
pub struct PrometheusMiddlewareLayer {
    metrics: Metrics,
}

impl PrometheusMiddlewareLayer {
    /// Create a new Prometheus middleware layer with the given metrics.
    pub fn new(metrics: Metrics) -> Self {
        Self { metrics }
    }
}

impl<S> Layer<S> for PrometheusMiddlewareLayer {
    type Service = PrometheusMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PrometheusMiddleware::new(inner, self.metrics.clone())
    }
}

/// Prometheus middleware for tracking control plane API metrics.
#[derive(Clone)]
pub struct PrometheusMiddleware<S> {
    inner: S,
    metrics: Metrics,
}

impl<S> PrometheusMiddleware<S> {
    /// Create a new Prometheus middleware with the given service and metrics.
    pub fn new(inner: S, metrics: Metrics) -> Self {
        Self { inner, metrics }
    }
}

impl<S> Service<Request<Body>> for PrometheusMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let method = request.uri().path().to_string();
        let metrics = self.metrics.clone();

        // Increment started metric
        metrics
            .control_plane_started_total
            .with_label_values(&[&method])
            .inc();

        let fut = self.inner.call(request);
        let start = Instant::now();

        Box::pin(async move {
            let result = fut.await.map_err(Into::into)?;
            let status = result.status().as_str().to_string();

            // Increment handled metric
            metrics
                .control_plane_handled_total
                .with_label_values(&[&method, &status])
                .inc();

            // Observe latency
            let elapsed = start.elapsed().as_secs_f64();
            metrics
                .control_plane_latency_seconds
                .with_label_values(&[&method, &status])
                .observe(elapsed);

            Ok(result)
        })
    }
}

/// SNAP control plane API metrics.
#[derive(Debug, Clone)]
pub struct Metrics {
    /// Total number of control plane API requests started on the server.
    pub control_plane_started_total: IntCounterVec,
    /// Total number of control plane API requests handled on the server.
    pub control_plane_handled_total: IntCounterVec,
    /// Latency of control plane API requests in seconds.
    pub control_plane_latency_seconds: HistogramVec,
}

impl Metrics {
    /// Create new metrics instance with the given registry.
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Metrics {
            control_plane_started_total: metrics_registry.int_counter_vec(
                "control_plane_requests_started_total",
                "Total number of control plane API requests started on the server.",
                &["method"],
            ),
            control_plane_handled_total: metrics_registry.int_counter_vec(
                "control_plane_requests_handled_total",
                "Total number of control plane API requests handled on the server.",
                &["method", "status"],
            ),
            control_plane_latency_seconds: metrics_registry.histogram_vec(
                "control_plane_requests_latency_seconds",
                "Latency of control plane API requests in seconds.",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
                &["method", "status"],
            ),
        }
    }
}
