//! Simulating a signing circuit
#![allow(non_snake_case)]
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::{AllocatedNum, Num},
  ConstraintSystem, SynthesisError,
};
use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use nova::traits::circuit::StepCircuit;

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};

/// Create a circuit that signs a message
#[derive(Clone)]
pub struct SigningCircuit<Scalar: PrimeField> {
  hash: Vec<u8>, // The hash of the message to be signed
  _p: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> SigningCircuit<Scalar> {
  /// Create a new signing circuit with the hash to be signed in input
  pub fn new(hash: Vec<u8>) -> Self {
    Self {
      hash,
      _p: PhantomData,
    }
  }
}

impl<Scalar: PrimeField + PrimeFieldBits> StepCircuit<Scalar> for SigningCircuit<Scalar> {
  fn arity(&self) -> usize {
    2
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
