//! Simulating a signing circuit
#![allow(non_snake_case)]

use zk_engine::precompiles::signing::{CompressedProof, SigningCircuit};

use serde::Serialize;
use std::time::Instant;

#[derive(Serialize)]
struct SendDataBody {
  data: String,
  snark: <SigningCircuit as CompressedProof>::CompressedProof,
  did: String,
}

fn main() {
  println!("=========================================================");
  println!("Nova-based Signing example");
  println!("=========================================================");

  let secret_key_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let secret_key = hex::decode(secret_key_hex).unwrap();

  let hash = [0u8; 32];
  let circuit_primary = SigningCircuit::new(hash.to_vec(), secret_key.to_vec());

  // Building circuit's public params
  let start = Instant::now();
  let pp = circuit_primary.get_public_params().unwrap();
  println!("Building public params took {:?}", start.elapsed());

  // produce a recursive SNARK
  println!("Generating a RecursiveSNARK...");
  let start = Instant::now();
  let recursive_snark = circuit_primary.prove(&pp).unwrap();

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
  println!("Output: {:?}", output);

  // produce a compressed SNARK
  println!("Compressing the RecursiveSNARK...");
  let start = Instant::now();

  let compressed_proof = SigningCircuit::compress_proof(&pp, &recursive_snark).unwrap();
  println!("CompressedSNARK::prove took {:?} ", start.elapsed());

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
  println!("Output: {:?}", output2);
  println!("=========================================================");

  let data = SendDataBody {
    data: "Hello, World!".to_string(),
    snark: compressed_proof,
    did: "did:nov:example".to_string(),
  };

  let data_json = serde_json::to_string(&data).unwrap();
  println!("Data to send: {}", data_json);
}
