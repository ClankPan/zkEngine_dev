use crate::{
  pcd::{prove_shard, verify_json_receipts},
  traits::wasm::{ZKWASMArgs, ZKWASMContext},
  wasm::{args::WASMArgsBuilder, ctx::wasi::WasiWASMCtx},
};
use anyhow::Ok;
use std::path::PathBuf;
use wasmi::TraceSliceValues;

/// Logic to get shard start and end opcodes
fn get_shard_start_end_values(
  step_length: usize,
  execution_trace_len: &usize,
) -> Vec<(usize, usize)> {
  let num_steps = execution_trace_len / step_length;
  let mut shard_start_end = Vec::new();

  for i in 0..num_steps {
    shard_start_end.push((i * step_length, (i + 1) * step_length));
  }

  if execution_trace_len % step_length != 0 {
    shard_start_end.push((step_length * num_steps, *execution_trace_len));
  }

  shard_start_end
}

#[test]
fn test_connect_shards() -> anyhow::Result<()> {
  let _ = tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .try_init();

  let step_length = 1_000;

  // Parameters to run the WASM module
  let file_path = PathBuf::from("wasm/misc/fib.wat");
  let invoked_fn_name = Some(String::from("fib"));
  let func_args = vec![String::from("580")];

  let wasm_args = WASMArgsBuilder::default()
    .file_path(file_path.clone())
    .invoke(invoked_fn_name.clone())
    .func_args(func_args.clone())
    .build();

  let bytecode = wasm_args.bytecode().unwrap();

  let mut wasm_ctx = WasiWASMCtx::new_from_file(&wasm_args)?;

  // Mock the lead node which first runs an estimate on WASM
  let (etable, _) = wasm_ctx.build_execution_trace()?;

  // Length used to determine which start and end opcodes each shard gets
  let execution_trace_len = etable.entries().len();

  // Get the start and end opcodes for each shard
  let shard_start_end = get_shard_start_end_values(step_length, &execution_trace_len);

  // Mock proving execution of shards with their start and end value and collect ther receipts to
  // testify a valid execution trace
  tracing::info!("proving shards");
  let mut receipt_vec = Vec::new();
  for (start, end) in shard_start_end {
    // Build WASM args for each shard
    let wasm_args = WASMArgsBuilder::default()
      .file_path(file_path.clone())
      .trace_slice_values(TraceSliceValues::new(start, end))
      .invoke(invoked_fn_name.clone())
      .func_args(func_args.clone())
      .build();

    let receipt = prove_shard(&bytecode, &wasm_args).unwrap();
    receipt_vec.push(receipt);
  }

  // Verify receipts are valid
  tracing::info!("verifying shard receipts");
  verify_json_receipts(receipt_vec)?;

  Ok(())
}
