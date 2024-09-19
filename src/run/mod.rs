//! The run module contains the different run strategies that can be used to run the zkVM.

pub mod batched;
pub mod default;

#[cfg(test)]
mod tests;

#[cfg(not(target_arch = "wasm32"))]
pub mod cli_utils {
  //! This module contains the CLI utilities for the zkEngine.
  use crate::{
    traits::{be_engine::PastaEngine, zkvm::ZKVM},
    wasm::{args::WASMArgs, ctx::wasi::WasiWASMCtx},
  };

  use super::{
    batched::{BatchedZKEExecutionProof, BatchedZKEProof},
    default::{ZKEExecutionProof, ZKEProof},
  };
  use crate::traits::wasm::ZKWASMArgs;
  use nova::{
    provider::{ipa_pc, PallasEngine},
    spartan::{self, snark::RelaxedR1CSSNARK},
    traits::Dual,
  };

  type E = PastaEngine;
  type E1 = PallasEngine;
  type EE1 = ipa_pc::EvaluationEngine<E1>;
  type EE2 = ipa_pc::EvaluationEngine<Dual<E1>>;
  type BS1 = spartan::batched::BatchedRelaxedR1CSSNARK<E1, EE1>;
  type S1 = RelaxedR1CSSNARK<E1, EE1>;
  type S2 = RelaxedR1CSSNARK<Dual<E1>, EE2>;

  /// Function for user to test the zkEngine
  ///
  /// # Note
  ///
  /// This is for testing purposes only
  pub fn prove_wasm_test(wasm_args: &WASMArgs, batched: bool) -> anyhow::Result<()> {
    // Get start flag or default to 0
    let start = wasm_args.trace_slice_values().start();

    // You cannot run MCC from any other starting point than 0
    // Therefore if start is not 0, we only run the execution proof
    // Otherwise we run both MCC and execution proof
    if start != 0 {
      tracing::info!("Adding start flag results in not running MCC proving");
      prove_execution(wasm_args, batched)
    } else {
      prove_mcc_and_execution(wasm_args, batched)
    }
  }

  /// Runs proving system on only execution trace
  pub fn prove_execution(wasm_args: &WASMArgs, batched: bool) -> anyhow::Result<()> {
    if batched {
      let pp = BatchedZKEExecutionProof::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      let _ = BatchedZKEExecutionProof::<E>::prove_wasm_execution(
        &mut WasiWASMCtx::new_from_file(wasm_args)?,
        &pp,
      )?;
    } else {
      let pp =
        ZKEExecutionProof::<E1, BS1, S1, S2>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      let _ = ZKEExecutionProof::<E1, BS1, S1, S2>::prove_wasm_execution(
        &mut WasiWASMCtx::new_from_file(wasm_args)?,
        &pp,
      )?;
    }
    Ok(())
  }

  /// Runs proving system on execution trace and memory trace
  fn prove_mcc_and_execution(wasm_args: &WASMArgs, batched: bool) -> anyhow::Result<()> {
    if batched {
      let pp = BatchedZKEProof::<E>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      BatchedZKEProof::<E>::prove_wasm(&mut WasiWASMCtx::new_from_file(wasm_args)?, &pp)?;
    } else {
      let pp = ZKEProof::<E1, BS1, S1, S2>::setup(&mut WasiWASMCtx::new_from_file(wasm_args)?)?;
      ZKEProof::<E1, BS1, S1, S2>::prove_wasm(&mut WasiWASMCtx::new_from_file(wasm_args)?, &pp)?;
    }
    Ok(())
  }
}
