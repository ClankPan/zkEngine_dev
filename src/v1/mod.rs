//! V1 of zkEngine: Implements the Nebula paper for WASM ISA
#![allow(clippy::type_complexity)]
pub mod error;
// pub mod aggregation;
// pub mod sharding;
pub mod utils;
pub mod wasm_ctx;
pub mod wasm_snark;

#[cfg(test)]
mod tests;
