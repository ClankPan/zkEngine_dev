use wasmi::WitnessVM;

use crate::v1::{
  error::ZKWASMError,
  wasm_ctx::{ExecutionTrace, ZKWASMCtx},
};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

/// Get inner value of [`Rc<RefCell<T>>`]
///
/// # Panics
///
/// Panics if [`Rc`] is not the sole owner of the underlying data,
pub fn unwrap_rc_refcell<T>(last_elem: Rc<RefCell<T>>) -> T {
  let inner: RefCell<T> = Rc::try_unwrap(last_elem)
    .unwrap_or_else(|_| panic!("The last_elem was shared, failed to unwrap"));
  inner.into_inner()
}

#[allow(dead_code)]
#[tracing::instrument(skip_all, name = "estimate_wasm")]
/// Get estimations of the WASM execution trace size
pub fn estimate_wasm(program: &impl ZKWASMCtx) -> Result<ExecutionTrace, ZKWASMError> {
  program.execution_trace()
}

/// Split vector and return Vec's
pub fn split_vector<T>(mut vec: Vec<T>, split_index: usize) -> (Vec<T>, Vec<T>) {
  let second_part = vec.split_off(split_index);
  (vec, second_part)
}

/// Count how many time an opcode gets used. Uses the J index of the opcode
pub fn count_opcodes(vms: &[WitnessVM]) -> HashMap<u64, usize> {
  let capacity = wasmi::Instruction::MAX_J + 1;

  let mut opcodes_count = HashMap::with_capacity(capacity as usize);

  for c in 0..capacity {
    opcodes_count.insert(c, 0);
  }

  for vm in vms {
    let instr_J = vm.instr.index_j();
    let count = opcodes_count.entry(instr_J).or_insert(0);
    *count += 1;
  }

  opcodes_count
}

#[cfg(test)]
mod test {
  use crate::v1::{
    utils::tracing::count_opcodes,
    wasm_ctx::{WASMArgsBuilder, WASMCtx, WasiWASMCtx, ZKWASMCtx},
  };
  use std::path::PathBuf;

  #[test]
  fn test_count_defi_transaction() {
    // Simulated user and pool balances
    let user_input_balance = "1000"; // User's balance of token A
    let pool_input_reserve = "10000"; // Pool's reserve of token A
    let pool_output_reserve = "10000"; // Pool's reserve of token B
    let swap_amount = "500"; // Amount of token A to swap for token B
    let price = "100"; // Price of token A in terms of token B

    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/use_cases/defi_transaction.wasm"))
      .unwrap()
      .func_args(vec![
        user_input_balance.to_string(),
        pool_input_reserve.to_string(),
        pool_output_reserve.to_string(),
        swap_amount.to_string(),
        price.to_string(),
      ])
      .invoke("main")
      .build();

    let wasm_ctx = WASMCtx::new(wasm_args);

    let (vms, _, _) = wasm_ctx.execution_trace().unwrap();
    println!("vms.len(): {:#?}", vms.len());

    let opcodes_count = count_opcodes(&vms);

    let instrs_to_count = [wasmi::Instruction::I64Add, wasmi::Instruction::I64Mul];

    for instr_to_count in instrs_to_count.iter() {
      println!(
        "{:?}: {:#?}",
        instr_to_count,
        opcodes_count[&instr_to_count.index_j()]
      );
    }
  }

  #[test]
  fn test_count_integer_hash() {
    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/nebula/integer_hash.wasm"))
      .unwrap()
      .func_args(vec!["100".to_string()])
      .invoke("integer_hash")
      .build();

    let wasm_ctx = WASMCtx::new(wasm_args);

    let (vms, _, _) = wasm_ctx.execution_trace().unwrap();
    println!("vms.len(): {:#?}", vms.len());

    let opcodes_count = count_opcodes(&vms);

    let instrs_to_count = [wasmi::Instruction::I64Add, wasmi::Instruction::I64Mul];

    for instr_to_count in instrs_to_count.iter() {
      println!(
        "{:?}: {:#?}",
        instr_to_count,
        opcodes_count[&instr_to_count.index_j()]
      );
    }
  }

  #[test]
  fn test_count_gradient_boosting() {
    let wasm_args = WASMArgsBuilder::default()
      .file_path(PathBuf::from("wasm/gradient_boosting.wasm"))
      .unwrap()
      .invoke("_start")
      .build();

    let wasm_ctx = WasiWASMCtx::new(wasm_args);

    let (vms, _, _) = wasm_ctx.execution_trace().unwrap();
    println!("vms.len(): {:#?}", vms.len());

    let opcodes_count = count_opcodes(&vms);

    let instrs_to_count = [wasmi::Instruction::I64Add, wasmi::Instruction::I64Mul];

    for instr_to_count in instrs_to_count.iter() {
      println!(
        "{:?}: {:#?}",
        instr_to_count,
        opcodes_count[&instr_to_count.index_j()]
      );
    }
  }
}
