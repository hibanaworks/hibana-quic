#![cfg(hibana_profile)]

fn samples(default: usize) -> usize {
    let samples = match std::env::var("HIBANA_PROJECTION_SAMPLES") {
        Ok(value) => value.parse::<usize>().expect("positive sample count"),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("sample count: {error}"),
    };
    assert!(samples != 0, "sample count must be positive");
    samples
}

fn measure(name: &str, samples: usize, run: impl Fn() -> bool) {
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = std::time::Instant::now();
        assert!(std::hint::black_box(run()));
        times.push(started.elapsed());
    }
    times.sort_unstable();
    eprintln!(
        "native {name} samples={samples} min={:?} median={:?}",
        times[0],
        times[samples / 2]
    );
}

#[test]
fn full_connection() {
    let samples = samples(100);
    let global = hibana_quic::quic::application::global::choreography();
    let expected = hibana::g::profiling::source(std::hint::black_box(&global));
    assert!(expected.receive_causal);
    eprintln!("{expected:?}");
    measure("lane-assignment", samples, || {
        hibana::g::profiling::source(std::hint::black_box(&global)) == expected
    });
}

#[test]
fn connection_operation_order() {
    use hibana_quic::quic::{application::global as app, global as prefix};
    let global = hibana_quic::quic::application::global::choreography();
    let samples = samples(10);
    measure("operation-order RX", samples, || {
        hibana::g::profiling::operation_order::<{ prefix::RX }>(&global)
    });
    measure("operation-order SOURCE", samples, || {
        hibana::g::profiling::operation_order::<{ app::SOURCE }>(&global)
    });
    measure("operation-order RECEIVE", samples, || {
        hibana::g::profiling::operation_order::<{ app::RECEIVE }>(&global)
    });
    measure("operation-order SINK", samples, || {
        hibana::g::profiling::operation_order::<{ app::SINK }>(&global)
    });
}

#[test]
fn connection_role_plan() {
    use hibana_quic::quic::{application::global as app, global as prefix};
    let global = hibana_quic::quic::application::global::choreography();
    let samples = samples(10);
    measure("role-plan RX", samples, || {
        hibana::g::profiling::role_plan::<{ prefix::RX }>(&global)
    });
    measure("role-plan SOURCE", samples, || {
        hibana::g::profiling::role_plan::<{ app::SOURCE }>(&global)
    });
    measure("role-plan RECEIVE", samples, || {
        hibana::g::profiling::role_plan::<{ app::RECEIVE }>(&global)
    });
    measure("role-plan SINK", samples, || {
        hibana::g::profiling::role_plan::<{ app::SINK }>(&global)
    });
}

#[test]
fn connection_resident_validation() {
    use hibana_quic::quic::{application::global as app, global as prefix};
    let global = hibana_quic::quic::application::global::choreography();
    let samples = samples(10);
    measure("resident-validation RX", samples, || {
        hibana::g::profiling::resident_validation::<{ prefix::RX }>(&global)
    });
    measure("resident-validation SOURCE", samples, || {
        hibana::g::profiling::resident_validation::<{ app::SOURCE }>(&global)
    });
    measure("resident-validation RECEIVE", samples, || {
        hibana::g::profiling::resident_validation::<{ app::RECEIVE }>(&global)
    });
    measure("resident-validation SINK", samples, || {
        hibana::g::profiling::resident_validation::<{ app::SINK }>(&global)
    });
}

#[test]
fn connection_source_emission() {
    let global = hibana_quic::quic::application::global::choreography();
    measure("source-emission", samples(10), || {
        hibana::g::profiling::source_emission(&global)
    });
}

#[test]
fn connection_actor_image() {
    let global = hibana_quic::quic::application::global::choreography();
    measure("actor-image", samples(10), || {
        hibana::g::profiling::actor_image(&global)
    });
}

#[test]
fn connection_scope_facts() {
    let global = hibana_quic::quic::application::global::choreography();
    measure("scope-facts", samples(10), || {
        hibana::g::profiling::scope_facts(&global)
    });
}

#[test]
fn connection_image_emission() {
    use hibana_quic::quic::{application::global as app, global as prefix};
    let global = hibana_quic::quic::application::global::choreography();
    let samples = samples(10);
    measure("image-emission RX", samples, || {
        hibana::g::profiling::image_emission::<{ prefix::RX }>(&global)
    });
    measure("image-emission SOURCE", samples, || {
        hibana::g::profiling::image_emission::<{ app::SOURCE }>(&global)
    });
    measure("image-emission RECEIVE", samples, || {
        hibana::g::profiling::image_emission::<{ app::RECEIVE }>(&global)
    });
    measure("image-emission SINK", samples, || {
        hibana::g::profiling::image_emission::<{ app::SINK }>(&global)
    });
}
