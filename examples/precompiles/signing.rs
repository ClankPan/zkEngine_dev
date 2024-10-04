//! Simulating a signing circuit
#![allow(non_snake_case)]
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::{AllocatedNum, Num},
  ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use ff::{Field, PrimeField, PrimeFieldBits};
use nova::{
  provider::{PallasEngine, VestaEngine},
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::default_ck_hint,
    Engine,
  },
  PublicParams, RecursiveSNARK,
};
use std::time::Instant;

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};

type E1 = PallasEngine;
type E2 = VestaEngine;

#[derive(Clone, Debug)]
struct SigningCircuit<Scalar: PrimeField> {
  hash: Vec<u8>, // The hash of the message to be signed
  _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> SigningCircuit<Scalar> {
  pub fn new(hash: Vec<u8>) -> Self {
    Self {
      hash,
      _p: PhantomData,
    }
  }
}

impl<Scalar: PrimeField + PrimeFieldBits> StepCircuit<Scalar> for SigningCircuit<Scalar> {
  fn arity(&self) -> usize {
    1
  }

  /// No clue if it is supposed to be incremental or external, just took a guess
  fn get_counter_type(&self) -> nova::StepCounterType {
    nova::StepCounterType::Incremental
  }

  fn synthesize<CS: ConstraintSystem<Scalar>>(
    &self,
    cs: &mut CS,
    _z: &[AllocatedNum<Scalar>],
  ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    let mut z_out: Vec<AllocatedNum<Scalar>> = Vec::new();

    let secret_key = b"0123456789abcdef0123456789abcdef";

    let (private_key, _) = create_key_pair_from_bytes(secret_key);

    let signature = sign_hash_slice(&private_key, &self.hash);
    let signature_bytes = signature.serialize_compact();

    let signature_values: Vec<_> = signature_bytes
      .into_iter()
      .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
      .map(Some)
      .collect();

    let signature_bits = signature_values
      .into_iter()
      .enumerate()
      .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("signature bit {i}")), b))
      .map(|b| b.map(Boolean::from))
      .collect::<Result<Vec<_>, _>>()?;

    for (i, sign_bits) in signature_bits.chunks(256_usize).enumerate() {
      let mut num = Num::<Scalar>::zero();
      let mut coeff = Scalar::ONE;
      for bit in sign_bits {
        num = num.add_bool_with_coeff(CS::one(), bit, coeff);

        coeff = coeff.double();
      }

      let sign = AllocatedNum::alloc(cs.namespace(|| format!("input {i}")), || {
        Ok(*num.get_value().get()?)
      })?;

      // num * 1 = sign
      cs.enforce(
        || format!("packing constraint {i}"),
        |_| num.lc(Scalar::ONE),
        |lc| lc + CS::one(),
        |lc| lc + sign.get_variable(),
      );
      z_out.push(sign);
    }

    Ok(z_out)
  }
}

fn create_key_pair_from_bytes(secret_bytes: &[u8]) -> (SecretKey, PublicKey) {
  let secp = Secp256k1::new();
  let secret_key = SecretKey::from_slice(secret_bytes).expect("32 bytes");
  let public_key = PublicKey::from_secret_key(&secp, &secret_key);
  (secret_key, public_key)
}

fn sign_hash_slice(secret_key: &SecretKey, hash: &[u8]) -> Signature {
  let message = Message::from_digest_slice(&hash).expect("32 bytes");
  let secp = Secp256k1::new();
  secp.sign_ecdsa(&message, &secret_key)
}

fn main() {
  println!("=========================================================");
  println!("Nova-based Signing example");
  println!("=========================================================");

  type C1 = SigningCircuit<<E1 as Engine>::Scalar>;
  type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

  let hash = [0u8; 32];
  let circuit_primary = C1::new(hash.to_vec());
  let circuit_secondary = TrivialCircuit::default();

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
    &[<E1 as Engine>::Scalar::zero()],
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
    &[<E1 as Engine>::Scalar::ZERO],
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
