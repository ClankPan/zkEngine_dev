//! Simulating a signing circuit
#![allow(non_snake_case)]
use ff::Field;
use nova::{
  provider::{PallasEngine, VestaEngine},
  traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
  PublicParams, RecursiveSNARK,
};

use zk_engine::precompiles::signing::SigningCircuit;

use std::time::Instant;

type E1 = PallasEngine;
type E2 = VestaEngine;

fn main() {
  println!("=========================================================");
  println!("Nova-based Signing example");
  println!("=========================================================");

  type C1 = SigningCircuit<<E1 as Engine>::Scalar>;
  type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

  let secret_key_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let secret_key = hex::decode(secret_key_hex).unwrap();

  let hash = [0u8; 32];
  let circuit_primary = C1::new(hash.to_vec(), secret_key.to_vec());
  let circuit_secondary = C2::default();

  // produce public parameters
  let start = Instant::now();
  println!("Producing public parameters...");
  let pp = PublicParams::<E1>::setup(
    &circuit_primary,
    &circuit_secondary,
    &*default_ck_hint(),
    &*default_ck_hint(),
  )
  .unwrap();
  println!("PublicParams::setup, took {:?} ", start.elapsed());

  // produce a recursive SNARK
  println!("Generating a RecursiveSNARK...");
  let mut recursive_snark: RecursiveSNARK<E1> = RecursiveSNARK::<E1>::new(
    &pp,
    &circuit_primary,
    &circuit_secondary,
    &[<E1 as Engine>::Scalar::zero(); 2], // Matching the arity
    &[<E2 as Engine>::Scalar::zero()],
  )
  .unwrap();

  let start = Instant::now();
  recursive_snark
    .prove_step(&pp, &circuit_primary, &circuit_secondary)
    .unwrap();

  println!("RecursiveSNARK::proving took {:?} ", start.elapsed());

  // verify the recursive SNARK
  println!("Verifying a RecursiveSNARK...");
  let res = recursive_snark.verify(
    &pp,
    1,
    &[<E1 as Engine>::Scalar::ZERO; 2], // Matching the arity
    &[<E2 as Engine>::Scalar::ZERO],
  );
  println!("RecursiveSNARK::verify: {:?}", res.is_ok(),);
  res.unwrap();

  // Skipped for now, needed more structs as EE1 and EE2, S1 and S2
  /*   // produce a compressed SNARK
  println!("Generating a CompressedSNARK using Spartan with HyperKZG...");
  let (pk, vk) = CompressedSNARK::<_, S1, S2>::setup(&pp).unwrap();

  let start = Instant::now();

  let res = CompressedSNARK::<_, S1, S2>::prove(&pp, &pk, &recursive_snark);
  println!(
    "CompressedSNARK::prove: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
  );
  assert!(res.is_ok());
  let compressed_snark = res.unwrap();

  let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
  bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
  let compressed_snark_encoded = encoder.finish().unwrap();
  println!(
    "CompressedSNARK::len {:?} bytes",
    compressed_snark_encoded.len()
  );

  // verify the compressed SNARK
  println!("Verifying a CompressedSNARK...");
  let start = Instant::now();
  let res = compressed_snark.verify(
    &vk,
    num_steps,
    &[<E1 as Engine>::Scalar::ZERO],
    &[<E2 as Engine>::Scalar::ZERO],
  );
  println!(
    "CompressedSNARK::verify: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
  );
  res.unwrap();
  println!("========================================================="); */
}
