//! Simulating a signing circuit
#![allow(non_snake_case)]

use zk_engine::precompiles::signing::{CircuitTypes, SigningCircuit};

use serde::Serialize;
use std::time::Instant;

#[derive(Serialize)]
struct SendDataBody {
  data: String,
  snark: <SigningCircuit as CircuitTypes>::CompressedProof,
  did: String,
}
type PP = <SigningCircuit as CircuitTypes>::PublicParams;
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
  let pp: nova::PublicParams<nova::provider::PallasEngine> =
    circuit_primary.get_public_params().unwrap();
  println!("Building public params took {:?}", start.elapsed());

  let pp_ser = serde_json::to_string(&pp).unwrap();

  let public_params_deser: PP = serde_json::from_str(&pp_ser).unwrap();
  // produce a recursive SNARK
  println!("Generating a RecursiveSNARK...");
  let start = Instant::now();
  let recursive_snark = circuit_primary.prove(&public_params_deser).unwrap();

  println!("RecursiveSNARK::proving took {:?} ", start.elapsed());

  // verify the recursive SNARK
  let start = Instant::now();

  println!("Verifying a RecursiveSNARK...");
  let res = SigningCircuit::verify(&public_params_deser, &recursive_snark);
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

  let compressed_proof =
    SigningCircuit::compress_proof(&public_params_deser, &recursive_snark).unwrap();
  println!("CompressedSNARK::prove took {:?} ", start.elapsed());

  // verify the compressed SNARK
  println!("Verifying a CompressedSNARK...");
  let start = Instant::now();
  let res = SigningCircuit::verify_compressed(&public_params_deser, &compressed_proof);
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
