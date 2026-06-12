use tracing_subscriber::{Layer, Registry};

pub type OtelLayer = Box<dyn Layer<Registry> + Send + Sync>;

#[cfg(feature = "otel")]
pub struct OtelGuard {
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

#[cfg(not(feature = "otel"))]
pub struct OtelGuard;

#[cfg(feature = "otel")]
impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

#[cfg(feature = "otel")]
pub fn init_layer(default_service_name: &str) -> anyhow::Result<(OtelGuard, Option<OtelLayer>)> {
    use std::time::Duration;

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::{KeyValue, global};
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

    if !otel_enabled() {
        return Ok((OtelGuard { provider: None }, None));
    }

    let endpoint =
        env_non_empty("SOLAND_OTEL_ENDPOINT").unwrap_or_else(|| "http://127.0.0.1:4317".to_owned());
    let timeout_seconds = env_u64("SOLAND_OTEL_TIMEOUT_SECS", 3).max(1);
    let sample_ratio = env_f64("SOLAND_OTEL_SAMPLE_RATIO", 1.0)?;
    if !(0.0..=1.0).contains(&sample_ratio) {
        anyhow::bail!("SOLAND_OTEL_SAMPLE_RATIO must be between 0.0 and 1.0");
    }
    let service_name = env_non_empty("SOLAND_OTEL_SERVICE_NAME")
        .unwrap_or_else(|| default_service_name.to_owned());

    global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(timeout_seconds))
        .build()?;
    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", service_name.clone()))
        .build();
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(sample_ratio))
        .build();
    let tracer = provider.tracer(service_name);
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);

    global::set_tracer_provider(provider.clone());

    Ok((
        OtelGuard {
            provider: Some(provider),
        },
        Some(Box::new(layer)),
    ))
}

#[cfg(not(feature = "otel"))]
pub fn init_layer(_default_service_name: &str) -> anyhow::Result<(OtelGuard, Option<OtelLayer>)> {
    if otel_enabled() {
        anyhow::bail!(
            "SOLAND_OTEL_EXPORTER is set, but this binary was built without the `otel` feature"
        );
    }
    Ok((OtelGuard, None))
}

fn otel_enabled() -> bool {
    env_non_empty("SOLAND_OTEL_EXPORTER")
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "otlp" | "1" | "true"))
        .unwrap_or(false)
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(feature = "otel")]
fn env_u64(name: &str, default: u64) -> u64 {
    env_non_empty(name)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

#[cfg(feature = "otel")]
fn env_f64(name: &str, default: f64) -> anyhow::Result<f64> {
    env_non_empty(name)
        .map(|value| value.parse::<f64>())
        .transpose()
        .map(|value| value.unwrap_or(default))
        .map_err(|error| anyhow::anyhow!("{name} must be a number: {error}"))
}
