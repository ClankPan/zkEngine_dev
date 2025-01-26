use std::path::PathBuf;

use super::{BatchedWasmTransitionCircuit, WASMTransitionCircuit};
use crate::{
  error::ZKWASMError,
  utils::logging::init_logger,
  wasm_ctx::{WASMArgsBuilder, WASMCtx, ZKWASMCtx},
  wasm_snark::{mcc::multiset_ops::step_RS_WS, StepSize},
};
use ff::Field;
use nova::{
  nebula::rs::{PublicParams, RecursiveSNARK},
  provider::Bn256EngineIPA,
  traits::{snark::default_ck_hint, CurveCycleEquipped, Engine},
};
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::{fmt, EnvFilter, Registry};
use tracing_texray::TeXRayLayer;
use wasmi::WitnessVM;

pub type E = Bn256EngineIPA;
type F = <E as Engine>::Scalar;

fn gen_pp<E>(step_size: StepSize) -> PublicParams<E>
where
  E: CurveCycleEquipped,
{
  PublicParams::<E>::setup(
    &BatchedWasmTransitionCircuit::empty(step_size.execution),
    &*default_ck_hint(),
    &*default_ck_hint(),
  )
}

fn test_wasm_ctx_with<E>(program: &impl ZKWASMCtx, step_size: StepSize) -> Result<(), ZKWASMError>
where
  E: CurveCycleEquipped,
{
  let pp = &gen_pp::<E>(step_size);
  let (mut execution_trace, IS, IS_sizes) = program.execution_trace()?;
  tracing::info!("execution trace: {:#?}", execution_trace);
  let mut RS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
  let mut WS: Vec<Vec<(usize, u64, u64)>> = Vec::new();
  let mut FS = IS.clone();
  let mut global_ts = 0;
  let pad_len =
    (step_size.execution - (execution_trace.len() % step_size.execution)) % step_size.execution;
  execution_trace.extend((0..pad_len).map(|_| WitnessVM::default()));
  let (pc, sp) = {
    let pc = E::Scalar::from(execution_trace[0].pc as u64);
    let sp = E::Scalar::from(execution_trace[0].pre_sp as u64);
    (pc, sp)
  };
  let circuits: Vec<WASMTransitionCircuit> = execution_trace
    .into_iter()
    .map(|vm| {
      let (step_rs, step_ws) = step_RS_WS(&vm, &mut FS, &mut global_ts, &IS_sizes);
      RS.push(step_rs.clone());
      WS.push(step_ws.clone());
      WASMTransitionCircuit::new(vm, step_rs, step_ws, IS_sizes)
    })
    .collect();
  let circuits = circuits
    .chunks(step_size.execution)
    .map(|chunk| BatchedWasmTransitionCircuit::new(chunk.to_vec()))
    .collect::<Vec<_>>();
  let z0 = vec![pc, sp];
  let mut IC_i = E::Scalar::ZERO;
  let mut rs = RecursiveSNARK::new(pp, &circuits[0], &z0)?;
  for circuit in circuits.iter() {
    rs.prove_step(pp, circuit, IC_i)?;
    IC_i = rs.increment_commitment(pp, circuit);
  }
  let num_steps = rs.num_steps();
  rs.verify(pp, num_steps, &z0, IC_i)?;
  Ok(())
}

#[test]
fn test_basic() {
  init_logger();
  let step_size = StepSize::new(1);
  let wasm_args = WASMArgsBuilder::default()
    .file_path(PathBuf::from("wasm/sb/basic.wat"))
    .unwrap()
    .build();
  let wasm_ctx = WASMCtx::new(wasm_args);
  tracing_texray::examine(tracing::info_span!("test_wasm_ctx_with"))
    .in_scope(|| test_wasm_ctx_with::<E>(&wasm_ctx, step_size).unwrap());
}

fn tracing_init() {
  // Create an EnvFilter that filters out spans below the 'info' level
  let filter = EnvFilter::new("arecibo=info");

  // Create a TeXRayLayer
  let texray_layer = TeXRayLayer::new();

  // Set up the global subscriber
  let subscriber = Registry::default()
    .with(filter)
    .with(fmt::layer())
    .with(texray_layer);
  tracing::subscriber::set_global_default(subscriber).expect("Failed to set global subscriber");
}
