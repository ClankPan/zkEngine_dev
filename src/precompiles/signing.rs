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
  provider::{ipa_pc, PallasEngine, VestaEngine},
  spartan::{ppsnark, snark},
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::RelaxedR1CSSNARKTrait,
    Engine,
  },
  CompressedSNARK, PublicParams, RecursiveSNARK,
};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use std::error;

/// Create a circuit that signs a message
/// The default scalar field is PallasEngine's scalar field
#[derive(Clone)]
pub struct SigningCircuit<Scalar: PrimeField = <E1 as Engine>::Scalar> {
  hash: Vec<u8>,       // The hash of the message to be signed
  secret_key: Vec<u8>, // The secret key to sign the message
  _p: PhantomData<Scalar>,
}

impl Default for SigningCircuit<<E1 as Engine>::Scalar> {
  fn default() -> Self {
    Self {
      hash: vec![0u8; 32],
      secret_key: vec![1u8; 32],
      _p: PhantomData,
    }
  }
}

impl<Scalar: PrimeField + PrimeFieldBits> SigningCircuit<Scalar> {
  /// Create a new signing circuit
  /// - hash: The hash of the message to be signed, as a 32bytes vector
  /// - secret_key: The secret key to sign the message, as a 32bytes vector
  pub fn new(hash: Vec<u8>, secret_key: Vec<u8>) -> Self {
    Self {
      hash,
      secret_key,
      _p: PhantomData,
    }
  }
}

impl<Scalar: PrimeField + PrimeFieldBits> StepCircuit<Scalar> for SigningCircuit<Scalar> {
  fn arity(&self) -> usize {
    4
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

    let (private_key, _) = create_key_pair_from_bytes(&self.secret_key.as_slice());

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

    for (i, sign_bits) in signature_bits.chunks(128_usize).enumerate() {
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

// Types to be used with circuit's default type parameter
type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = ppsnark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = snark::RelaxedR1CSSNARK<E2, EE2>;

/// Holds the type for the compressed proof of the signing circuit
pub trait CircuitTypes {
  /// The type of the public params
  type PublicParams;
  /// The type of the compressed proof
  type CompressedProof;
}

impl CircuitTypes for SigningCircuit<<E1 as Engine>::Scalar> {
  type CompressedProof = CompressedSNARK<E1, S1, S2>;
  type PublicParams = PublicParams<E1>;
}

impl SigningCircuit<<E1 as Engine>::Scalar> {
  /// Builds the public parameters for the circuit
  pub fn get_public_params(&self) -> Result<PublicParams<E1>, Box<dyn error::Error>> {
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

    let circuit_secondary = C2::default();

    let pp =
      PublicParams::<E1>::setup(self, &circuit_secondary, &*S1::ck_floor(), &*S2::ck_floor())?;

    Ok(pp)
  }

  /// Proves the circuit, this function builds the public params and returns a recursive SNARK
  pub fn prove(
    &self,
    public_params: &PublicParams<E1>,
  ) -> Result<RecursiveSNARK<E1>, Box<dyn error::Error>> {
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
    let circuit_secondary = C2::default();
    let z0_primary = [<E1 as Engine>::Scalar::ZERO; 4];
    let z0_secondary = [<E2 as Engine>::Scalar::ZERO];

    let mut recursive_snark: RecursiveSNARK<E1> = RecursiveSNARK::<E1>::new(
      &public_params,
      self,
      &circuit_secondary,
      &z0_primary,
      &z0_secondary,
    )?;

    recursive_snark.prove_step(&public_params, self, &circuit_secondary)?;

    Ok(recursive_snark)
  }

  /// Compressed a recursive SNARK into a compressed SNARK, using the circuit public params
  pub fn compress_proof(
    public_params: &PublicParams<E1>,
    recursive_snark: &RecursiveSNARK<E1>,
  ) -> Result<CompressedSNARK<E1, S1, S2>, Box<dyn error::Error>> {
    let (pk, _) = CompressedSNARK::<E1, S1, S2>::setup(&public_params)?;
    let compressed_proof =
      CompressedSNARK::<E1, S1, S2>::prove(&public_params, &pk, recursive_snark)?;
    Ok(compressed_proof)
  }

  /// Verifies a recursive SNARK, returns the field elements of the circuit output
  pub fn verify(
    public_params: &PublicParams<E1>,
    recursive_snark: &RecursiveSNARK<E1>,
  ) -> Result<Vec<<E1 as Engine>::Scalar>, Box<dyn error::Error>> {
    let z0_primary = [<E1 as Engine>::Scalar::ZERO; 4];
    let z0_secondary = [<E2 as Engine>::Scalar::ZERO];

    let res = recursive_snark.verify(&public_params, 1, &z0_primary, &z0_secondary);
    let (vec, _) = res?;

    Ok(vec)
  }

  /// Verifies a compressed SNARK, returns the field elements of the circuit output
  pub fn verify_compressed(
    public_params: &PublicParams<E1>,
    compressed_proof: &CompressedSNARK<E1, S1, S2>,
  ) -> Result<Vec<<E1 as Engine>::Scalar>, Box<dyn error::Error>> {
    let z0_primary = [<E1 as Engine>::Scalar::ZERO; 4];
    let z0_secondary = [<E2 as Engine>::Scalar::ZERO];

    let (_, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params)?;
    let (res, _) = compressed_proof.verify(&vk, 1, &z0_primary, &z0_secondary)?;

    Ok(res)
  }
}
