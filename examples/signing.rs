//! Simulating a signing circuit
#![allow(non_snake_case)]
use ff::Field;
use nova::{provider::PallasEngine, traits::Engine};

use zk_engine::precompiles::signing::SigningCircuit;

use std::time::Instant;

type E1 = PallasEngine;

fn main() {
  println!("=========================================================");
  println!("Nova-based Signing example");
  println!("=========================================================");

  type C1 = SigningCircuit<<E1 as Engine>::Scalar>;

  let secret_key_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let secret_key = hex::decode(secret_key_hex).unwrap();

  let hash = [0u8; 32];
  let circuit_primary = C1::new(hash.to_vec(), secret_key.to_vec());

  // produce public parameters
  /*   let start = Instant::now();
  println!("Producing public parameters...");
  let pp = circuit_primary.get_public_params().unwrap();
  println!("PublicParams::setup, took {:?} ", start.elapsed()); */

  // produce a recursive SNARK
  println!("Building pp and generating a RecursiveSNARK...");
  let start = Instant::now();
  let mut recursive_snark = circuit_primary.prove().unwrap();

  println!("RecursiveSNARK::proving took {:?} ", start.elapsed());

  // verify the recursive SNARK
  let start = Instant::now();
  // getting the public params for this circuit, can be done from any instance of the circuit
  let pp = SigningCircuit::default().get_public_params().unwrap();

  println!("Verifying a RecursiveSNARK...");
  let res = SigningCircuit::verify(&pp, &recursive_snark);
  println!(
    "RecursiveSNARK::verify: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
  );
  assert!(res.is_ok());
  let output = res.unwrap();

  // produce a compressed SNARK
  let start = Instant::now();

  let compressed_proof = SigningCircuit::compress_proof(&pp, &recursive_snark).unwrap();

  // verify the compressed SNARK
  println!("Verifying a CompressedSNARK...");
  let start = Instant::now();
  let res = SigningCircuit::verify_compressed(&pp, &compressed_proof);
  println!(
    "CompressedSNARK::verify: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
  );
  let output2 = res.unwrap();
  println!("=========================================================");
}
