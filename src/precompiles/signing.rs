//! Simulating a signing circuit
#![allow(non_snake_case)]
use bellpepper_core::{boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError};
use bp_ecdsa::{curve::AllocatedAffinePoint, ecdsa::verify_eff};
use crypto_bigint::U256;
use ff::{Field, PrimeField, PrimeFieldBits};
use nova::{
  provider::{ipa_pc, Secp256k1Engine, Secq256k1Engine},
  spartan::{ppsnark, snark},
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::RelaxedR1CSSNARKTrait,
    Engine,
  },
  CompressedSNARK, PublicParams, RecursiveSNARK,
};
use std::error;

// Types to be used with circuit's default type parameter
type E1 = Secp256k1Engine;
type E2 = Secq256k1Engine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = ppsnark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = snark::RelaxedR1CSSNARK<E2, EE2>;

// Working on Secq, so Fq is base field and Fp is scalar field
// We need Fp as scalar field as signing circuit uses Fp, and building the proof requires the scalar field
type Fp = <E2 as Engine>::Scalar;

/// Create a circuit that signs a message
/// The default scalar field is PallasEngine's scalar field
#[derive(Clone)]
pub struct SigningCircuit<Scalar: PrimeField = Fp> {
  scalar: U256,
  t_x: Scalar,
  t_y: Scalar,
  u_x: Scalar,
  u_y: Scalar,
  public_key_x: Scalar,
  public_key_y: Scalar,
}

impl<Scalar: PrimeField + PrimeFieldBits> SigningCircuit<Scalar> {
  /// Create a new signing circuit
  /// - hash: The hash of the message to be signed, as a 32bytes vector
  /// - secret_key: The secret key to sign the message, as a 32bytes vector
  pub fn new(
    scalar: U256,
    t_x: Scalar,
    t_y: Scalar,
    u_x: Scalar,
    u_y: Scalar,
    public_key_x: Scalar,
    public_key_y: Scalar,
  ) -> Self {
    Self {
      scalar,
      t_x,
      t_y,
      u_x,
      u_y,
      public_key_x,
      public_key_y,
    }
  }
}

impl<Scalar: PrimeField<Repr = [u8; 32]> + PrimeFieldBits> StepCircuit<Scalar>
  for SigningCircuit<Scalar>
{
  fn arity(&self) -> usize {
    0
  }

  fn get_counter_type(&self) -> nova::StepCounterType {
    nova::StepCounterType::Incremental
  }

  fn synthesize<CS: ConstraintSystem<Scalar>>(
    &self,
    cs: &mut CS,
    _z: &[AllocatedNum<Scalar>],
  ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    let t_alloc = AllocatedAffinePoint::alloc_affine_point(cs, self.t_x, self.t_y)?;

    let u_alloc = AllocatedAffinePoint::alloc_affine_point(cs, self.u_x, self.u_y)?;

    let public_key_alloc =
      AllocatedAffinePoint::alloc_affine_point(cs, self.public_key_x, self.public_key_y)?;

    let out = verify_eff(cs, self.scalar, t_alloc, u_alloc, public_key_alloc).unwrap();

    match Boolean::enforce_equal(cs, &out, &Boolean::Constant(true)) {
      Ok(_) => Ok(vec![]),
      Err(e) => Err(e),
    }
  }
}

/// Holds the type for the compressed proof of the signing circuit
pub trait CircuitTypes {
  /// The type of the public params
  type PublicParams;
  /// The type of the compressed proof
  type CompressedProof;
}

impl CircuitTypes for SigningCircuit<Fp> {
  type CompressedProof = CompressedSNARK<E2, S2, S1>;
  type PublicParams = PublicParams<E2>;
}

/// Builds the public parameters for the circuit
pub fn get_public_params(
  circuit: &SigningCircuit<Fp>,
) -> Result<PublicParams<E2>, Box<dyn error::Error>> {
  type C2 = TrivialCircuit<<E1 as Engine>::Scalar>;

  let circuit_secondary = C2::default();

  let pp = PublicParams::<E2>::setup(
    circuit,
    &circuit_secondary,
    &*S2::ck_floor(),
    &*S1::ck_floor(),
  )?;

  Ok(pp)
}

/// Proves the circuit, this function builds the public params and returns a recursive SNARK
pub fn prove(
  circuit: &SigningCircuit<Fp>,
  public_params: &PublicParams<E2>,
) -> Result<RecursiveSNARK<E2>, Box<dyn error::Error>> {
  type C2 = TrivialCircuit<<E1 as Engine>::Scalar>;
  let circuit_secondary = C2::default();
  let z0_primary = [<E2 as Engine>::Scalar::ZERO];
  let z0_secondary = [<E1 as Engine>::Scalar::ZERO];

  let mut recursive_snark: RecursiveSNARK<E2> = RecursiveSNARK::<E2>::new(
    &public_params,
    circuit,
    &circuit_secondary,
    &z0_primary,
    &z0_secondary,
  )?;

  recursive_snark.prove_step(&public_params, circuit, &circuit_secondary)?;

  Ok(recursive_snark)
}

/// Compressed a recursive SNARK into a compressed SNARK, using the circuit public params
pub fn compress_proof(
  public_params: &PublicParams<E2>,
  recursive_snark: &RecursiveSNARK<E2>,
) -> Result<CompressedSNARK<E2, S2, S1>, Box<dyn error::Error>> {
  let (pk, _) = CompressedSNARK::<E2, S2, S1>::setup(&public_params)?;
  let compressed_proof =
    CompressedSNARK::<E2, S2, S1>::prove(&public_params, &pk, recursive_snark)?;
  Ok(compressed_proof)
}

/// Verifies a recursive SNARK, returns the field elements of the circuit output
pub fn verify(
  public_params: &PublicParams<E2>,
  recursive_snark: &RecursiveSNARK<E2>,
) -> Result<Vec<<E2 as Engine>::Scalar>, Box<dyn error::Error>> {
  let z0_primary = [<E2 as Engine>::Scalar::ZERO];
  let z0_secondary = [<E1 as Engine>::Scalar::ZERO];

  let res = recursive_snark.verify(&public_params, 1, &z0_primary, &z0_secondary);
  let (vec, _) = res?;

  Ok(vec)
}

/// Verifies a compressed SNARK, returns the field elements of the circuit output
pub fn verify_compressed(
  public_params: &PublicParams<E2>,
  compressed_proof: &CompressedSNARK<E2, S2, S1>,
) -> Result<Vec<<E2 as Engine>::Scalar>, Box<dyn error::Error>> {
  let z0_primary = [<E2 as Engine>::Scalar::ZERO];
  let z0_secondary = [<E1 as Engine>::Scalar::ZERO];

  let (_, vk) = CompressedSNARK::<E2, S2, S1>::setup(&public_params)?;
  let (res, _) = compressed_proof.verify(&vk, 1, &z0_primary, &z0_secondary)?;

  Ok(res)
}
