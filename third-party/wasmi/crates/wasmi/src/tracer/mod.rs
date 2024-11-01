use core::cmp;

use crate::engine::bytecode::Instruction;

#[derive(Debug, Clone, Default)]
/// Hold the execution trace from VM execution and manages other miscellaneous
/// information needed by the zkWASM
pub struct Tracer {
    /// Holds the VM state at each timestamp of the execution
    pub(crate) execution_trace: Vec<WitnessVM>,
    /// This is used to maintain the max stack address. We use this to
    /// construct the IS for MCC
    max_sp: usize,
}

impl Tracer {
    /// Creates a new [`TracerV0`] for generating execution trace during VM
    /// execution
    pub fn new() -> Self {
        Tracer::default()
    }

    /// Extract the execution trace from the tracer
    pub fn into_execution_trace(self) -> Vec<WitnessVM> {
        self.execution_trace
    }

    /// Used during execution to get the current timestamp of the execution step
    pub(crate) fn ts(&self) -> usize {
        self.execution_trace.len()
    }

    /// Check if executions step sp is greater than maintained tracers max_sp.
    /// If so update tracers max sp
    pub(crate) fn update_max_sp(&mut self, new_sp: usize) {
        self.max_sp = cmp::max(self.max_sp, new_sp);
    }

    /// Getter for max_sp
    pub(crate) fn max_sp(&self) -> usize {
        self.max_sp
    }
}

/// The VM state at each step of execution
#[derive(Clone, Debug, Default)]
pub struct WitnessVM {
    /// Stack pointer before execution
    pub(crate) pre_sp: usize,
    /// Program counter (InstructionPtr) before execution
    pub(crate) pc: usize,
    /// Explict trace of instruction. Used to determine read and write for MCC
    pub(crate) instr: Instruction,
    /// Unique index for the opcode type
    pub(crate) J: u64,
    /// Timestamp of execution
    pub(crate) ts: usize,
    /// First argument value.
    pub(crate) X: u64,
    /// Second argument value.
    pub(crate) Y: u64,
    /// Result of instuction.
    pub(crate) Z: u64,
}
