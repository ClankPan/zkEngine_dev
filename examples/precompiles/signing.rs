//! Simulating a signing circuit
#![allow(non_snake_case)]
use bellpepper::gadgets::{sha256::sha256, Assignment};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::{AllocatedNum, Num},
  ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use core::time::Duration;
use criterion::*;
use ff::{PrimeField, PrimeFieldBits};
use nova::{
  provider::{PallasEngine, VestaEngine},
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::default_ck_hint,
    Engine,
  },
  PublicParams, RecursiveSNARK,
};

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

type E1 = PallasEngine;
type E2 = VestaEngine;

#[derive(Clone, Debug)]
struct SigningCircuit<Scalar: PrimeField> {
  preimage: Vec<u8>, // The hash of the message to be signed
  _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> SigningCircuit<Scalar> {
  pub fn new(preimage: Vec<u8>) -> Self {
    Self {
      preimage,
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
    z: &[AllocatedNum<Scalar>],
  ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    let mut z_out: Vec<AllocatedNum<Scalar>> = Vec::new();

    let secret_key_repr = z[0]
      .get_value()
      .ok_or(SynthesisError::AssignmentMissing)?
      .to_repr();

    let secret_key = secret_key_repr.as_ref();

    let (private_key, _) = create_key_pair_from_bytes(secret_key);

    let signature = sign_hash_slice(&private_key, &self.preimage);
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

criterion_group! {
name = recursive_snark;
config = Criterion::default().warm_up_time(Duration::from_millis(3000));
targets = bench_recursive_snark
}

criterion_main!(recursive_snark);

fn bench_recursive_snark(c: &mut Criterion) {
  // Test vectors
  let circuits = vec![
    SigningCircuit::new(vec![0u8; 1 << 6]),
    SigningCircuit::new(vec![0u8; 1 << 7]),
    SigningCircuit::new(vec![0u8; 1 << 8]),
    SigningCircuit::new(vec![0u8; 1 << 9]),
    SigningCircuit::new(vec![0u8; 1 << 10]),
    SigningCircuit::new(vec![0u8; 1 << 11]),
    SigningCircuit::new(vec![0u8; 1 << 12]),
    SigningCircuit::new(vec![0u8; 1 << 13]),
    SigningCircuit::new(vec![0u8; 1 << 14]),
    SigningCircuit::new(vec![0u8; 1 << 15]),
    SigningCircuit::new(vec![0u8; 1 << 16]),
  ];

  for circuit_primary in circuits {
    let mut group = c.benchmark_group(format!(
      "NovaProve-Sha256-message-len-{}",
      circuit_primary.preimage.len()
    ));
    group.sample_size(10);

    // Produce public parameters
    let ttc = TrivialCircuit::default();
    let pp = PublicParams::<E1>::setup(
      &circuit_primary,
      &ttc,
      &*default_ck_hint(),
      &*default_ck_hint(),
    )
    .unwrap();

    let circuit_secondary = TrivialCircuit::default();
    let z0_primary = vec![<E1 as Engine>::Scalar::from(2u64)];
    let z0_secondary = vec![<E2 as Engine>::Scalar::from(2u64)];

    group.bench_function("Prove", |b| {
      b.iter(|| {
        let mut recursive_snark = RecursiveSNARK::new(
          black_box(&pp),
          black_box(&circuit_primary),
          black_box(&circuit_secondary),
          black_box(&z0_primary),
          black_box(&z0_secondary),
        )
        .unwrap();

        // produce a recursive SNARK for a step of the recursion
        assert!(recursive_snark
          .prove_step(
            black_box(&pp),
            black_box(&circuit_primary),
            black_box(&circuit_secondary),
          )
          .is_ok());
      })
    });
    group.finish();
  }
}
