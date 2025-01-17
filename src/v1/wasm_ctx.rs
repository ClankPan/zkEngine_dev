//! Implementation of WASM execution context for zkVM
use super::error::ZKWASMError;
use crate::{
  utils::wasm::{decode_func_args, prepare_func_results, read_wasm_or_wat},
  v1::utils::tracing::unwrap_rc_refcell,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, cmp, path::PathBuf, rc::Rc};
use wasmi::{Tracer, WitnessVM};
use wasmi_wasi::{clocks_ctx, sched_ctx, Table, WasiCtx};

/// Builder for [`WASMArgs`]. Constructs the arguments needed to construct a WASM execution context
/// that will be used for proving.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WASMArgsBuilder {
  program: Vec<u8>,
  invoke: String,
  func_args: Vec<String>,
  trace_slice_vals: Option<TraceSliceValues>,
}

impl WASMArgsBuilder {
  /// Set the program bytecode from file
  pub fn file_path(mut self, path: PathBuf) -> Result<Self, ZKWASMError> {
    let bytecode =
      read_wasm_or_wat(&path).map_err(|err| ZKWASMError::WASMError(err.to_string()))?;
    self.program = bytecode;
    Ok(self)
  }

  /// Set the program bytecode
  pub fn bytecode(mut self, program: Vec<u8>) -> Self {
    self.program = program;
    self
  }

  /// Set the WASM function to invoke
  pub fn invoke(mut self, invoke: &str) -> Self {
    self.invoke = invoke.to_string();
    self
  }

  /// Set the function arguments
  pub fn func_args(mut self, func_args: Vec<String>) -> Self {
    self.func_args = func_args;
    self
  }

  /// Set the `start` and `end` values to slice the execution trace
  pub fn trace_slice(mut self, trace_slice_vals: TraceSliceValues) -> Self {
    self.trace_slice_vals = Some(trace_slice_vals);
    self
  }

  /// Build the [`WASMArgs`] from the builder
  pub fn build(self) -> WASMArgs {
    WASMArgs {
      program: self.program,
      func_args: self.func_args,
      invoke: self.invoke,
      trace_slice_vals: self.trace_slice_vals,
    }
  }
}

/// Arguments needed to construct a WASM execution context that will be used for proving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WASMArgs {
  pub(in crate::v1) program: Vec<u8>,
  pub(in crate::v1) invoke: String,
  pub(in crate::v1) func_args: Vec<String>,
  pub(in crate::v1) trace_slice_vals: Option<TraceSliceValues>,
}

impl WASMArgs {
  /// Get the start value of the trace slice
  pub fn start(&self) -> usize {
    self
      .trace_slice_vals
      .map(|val| val.start())
      .unwrap_or_default()
  }

  /// Check if program is being sharded
  pub fn is_sharded(&self) -> bool {
    self.start() != 0
  }

  /// Get the shard_size
  pub fn shard_size(&self) -> Option<usize> {
    self.trace_slice_vals.map(|val| val.shard_size())
  }

  /// Get reference to bytecode.
  pub fn bytecode(&self) -> &[u8] {
    &self.program
  }

  /// Get the end slice value after WASM execution
  pub fn end(&self, execution_trace_len: usize) -> Result<usize, ZKWASMError> {
    self.validate_trace_slice_vals()?;
    Ok(self.calculate_end_slice_value(execution_trace_len))
  }

  /// Calculate the end slice value considering the execution trace length
  fn calculate_end_slice_value(&self, execution_trace_len: usize) -> usize {
    self.trace_slice_vals.map_or(execution_trace_len, |val| {
      if val.end() == 0 {
        execution_trace_len
      } else {
        cmp::min(val.end(), execution_trace_len)
      }
    })
  }

  /// Validate the [`TraceSliceValues`]
  pub fn validate_trace_slice_vals(&self) -> Result<(), ZKWASMError> {
    if let Some(val) = self.trace_slice_vals {
      if self.is_invalid_end_start_relation(&val) {
        return Err(self.invalid_trace_slice_error("End value cannot be 0 if start value is not 0 (default case) or start value cannot be greater than end value"));
      }
    }
    Ok(())
  }

  /// Helper function to check the invalid end-start relationship
  fn is_invalid_end_start_relation(&self, val: &TraceSliceValues) -> bool {
    val.end() == 0 && val.start() != 0 || val.start() != 0 && val.start() >= val.end()
  }

  /// Helper function to create the invalid trace slice error
  fn invalid_trace_slice_error(&self, message: &str) -> ZKWASMError {
    ZKWASMError::InvalidTraceSliceValues(message.to_string())
  }
}

impl Default for WASMArgsBuilder {
  fn default() -> Self {
    Self {
      program: vec![],
      invoke: "main".to_string(),
      func_args: vec![],
      trace_slice_vals: None,
    }
  }
}

/// Used to set start and end values to slice execution trace. Used in sharding/continuations
#[derive(Debug, Clone, Default, Copy, Serialize, Deserialize)]
pub struct TraceSliceValues {
  /// Start opcode
  pub(crate) start: usize,
  /// End opcode
  pub(crate) end: usize,
}

impl TraceSliceValues {
  /// Build new [`TraceSliceValues`]
  pub fn new(start: usize, end: usize) -> Self {
    TraceSliceValues { start, end }
  }

  /// Get start value
  pub fn start(&self) -> usize {
    self.start
  }

  /// Get end value
  pub fn end(&self) -> usize {
    self.end
  }

  /// Setter for start value
  pub fn set_start(&mut self, start: usize) {
    self.start = start;
  }

  /// Setter for end value
  pub fn set_end(&mut self, end: usize) {
    self.end = end;
  }

  /// Calculate the shard_size
  pub fn shard_size(&self) -> usize {
    self.end - self.start
  }
}

/// Execution trace, Initial memory trace, Initial stack trace length, Initial linear memory length
pub type ExecutionTrace = (Vec<WitnessVM>, Vec<(usize, u64, u64)>, ISMemSizes);

/// Definition for WASM execution context
pub trait ZKWASMCtx {
  /// Data type used in wasmi::Store
  type T;

  /// create store
  fn create_store(engine: &wasmi::Engine) -> wasmi::Store<Self::T>;

  /// create linker
  fn create_linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError>;

  /// Getter for WASM args
  fn args(&self) -> &WASMArgs;

  /// Get the execution trace from WASM execution context
  fn execution_trace(&self) -> Result<ExecutionTrace, ZKWASMError> {
    // Execute WASM module and build execution trace documenting vm state at
    // each step. Also get meta-date from execution like the max height of the [`ValueStack`]
    let tracer = Rc::new(RefCell::new(Tracer::new()));
    // Setup and parse the wasm bytecode.
    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, &self.args().program[..])?;

    // Create a new store and linker
    let mut store = Self::create_store(&engine);
    let linker = Self::create_linker(&engine)?;

    // Instantiate the module and trace WASM linear memory and global memory initializations
    let instance = linker
      .instantiate_with_trace(&mut store, &module, tracer.clone())?
      .start(&mut store)?;

    // Get the WASM module function we are going to invoke.
    let func = instance
      .get_func(&store, &self.args().invoke)
      .ok_or_else(|| {
        ZKWASMError::WasmiError(wasmi::Error::Func(
          wasmi::errors::FuncError::ExportedFuncNotFound,
        ))
      })?;

    // Prepare i/o for the function call.
    let ty = func.ty(&store);
    let func_args = decode_func_args(&ty, &self.args().func_args)?;
    let mut func_results = prepare_func_results(&ty);

    // Call the function to invoke.
    func.call_with_trace(&mut store, &func_args, &mut func_results, tracer.clone())?;
    tracing::debug!("wasm func res: {:#?}", func_results);

    // Extract the execution trace produced from WASM execution.
    //
    // [`unwrap_rc_refcell`] is safe to use here since this parent function ensures that the [`Rc`]
    // is the sole owner of the execution trace.
    let tracer = unwrap_rc_refcell(tracer);

    // Get the MCC values used to construct the initial memory state of the zkWASM.
    let IS_stack_len = tracer.IS_stack_len();
    let IS_mem_len = tracer.IS_mem_len();
    let IS = tracer.IS();

    // Take ownership of the execution trace of type [`Vec<WitnessVM>`] because the zkWASM needs
    // this type to execute.
    let execution_trace = tracer.into_execution_trace();

    // If only proving a portion of the execution trace (a shard) calculate the end value to slice
    // execution trace and use it to slice the execution trace.
    //
    // # Note:
    //
    // We do not use the `start` value to slice the execution trace because we need the execution
    // trace from opcode 0 to opcode `start` to construct the initial memory state of the shard.
    let end_slice = self.args().end(execution_trace.len())?;
    let execution_trace = execution_trace[..end_slice].to_vec();

    Ok((
      execution_trace,
      IS,
      ISMemSizes::new(IS_stack_len, IS_mem_len),
    ))
  }
}

#[derive(Debug, Clone)]
/// A type used to construct a WASM execution context used for proving.
pub struct WASMCtx {
  args: WASMArgs,
}

impl WASMCtx {
  /// Create a new instance of [`WASMCtx`]
  pub fn new(args: WASMArgs) -> Self {
    Self { args }
  }
}

impl ZKWASMCtx for WASMCtx {
  type T = ();

  fn create_store(engine: &wasmi::Engine) -> wasmi::Store<Self::T> {
    wasmi::Store::new(engine, ())
  }

  fn create_linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError> {
    Ok(<wasmi::Linker<()>>::new(engine))
  }

  fn args(&self) -> &WASMArgs {
    &self.args
  }
}

/// Wasm execution context
#[derive(Debug, Clone)]
pub struct WasiWASMCtx {
  args: WASMArgs,
}

impl WasiWASMCtx {
  /// Create a new instance of [`WasiWASMCtx`]
  pub fn new(args: WASMArgs) -> Self {
    Self { args }
  }
}

impl ZKWASMCtx for WasiWASMCtx {
  type T = WasiCtx;

  fn args(&self) -> &WASMArgs {
    &self.args
  }

  fn create_store(engine: &wasmi::Engine) -> wasmi::Store<Self::T> {
    let wasi = WasiCtx::new(zkvm_random_ctx(), clocks_ctx(), sched_ctx(), Table::new());
    wasmi::Store::new(engine, wasi)
  }

  fn create_linker(engine: &wasmi::Engine) -> Result<wasmi::Linker<Self::T>, ZKWASMError> {
    let mut linker = <wasmi::Linker<WasiCtx>>::new(engine);
    wasmi_wasi::add_to_linker(&mut linker, |ctx| ctx)?;
    Ok(linker)
  }
}

/// zkvm uses a seed to generate random numbers.
pub fn zkvm_random_ctx() -> Box<dyn RngCore + Send + Sync> {
  Box::new(StdRng::from_seed([0; 32]))
}

/// # Initial Set (IS) Memory Sizes.
///
/// i.e. Memory sizes for the initial state.
/// We need to know the sizes of the stack and linear
/// memory of the WASM module to initialize the initial memory state of the zkVM.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ISMemSizes {
  IS_stack_len: usize,
  IS_mem_len: usize,
}

impl ISMemSizes {
  /// Create a new instance of [`ISMemSizes`]
  pub fn new(IS_stack_len: usize, IS_mem_len: usize) -> Self {
    Self {
      IS_stack_len,
      IS_mem_len,
    }
  }

  /// Get the stack length
  pub fn stack_len(&self) -> usize {
    self.IS_stack_len
  }

  /// Get the memory length
  pub fn mem_len(&self) -> usize {
    self.IS_mem_len
  }
}
