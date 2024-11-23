//! Simulating a signing circuit
#![allow(non_snake_case)]
use bellpepper_core::{boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError};
use bp_ecdsa::{curve::AllocatedAffinePoint, ecdsa::verify_eff};
use crypto_bigint::{Encoding, U256};
use ff::{Field, PrimeField, PrimeFieldBits};
use halo2curves::{group::Group, CurveExt};
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
use rand::rngs::OsRng;
use std::error;
use std::ops::{Mul, Neg};

type Fp = <E1 as Engine>::Base;
type Fq = <E1 as Engine>::Scalar;
type Point = <E1 as Engine>::GE;

/// Create a circuit that signs a message
/// The default scalar field is PallasEngine's scalar field
#[derive(Clone)]
pub struct SigningCircuit<Scalar: PrimeField = Fq> {
  scalar: U256,
  t_x: Scalar,
  t_y: Scalar,
  u_x: Scalar,
  u_y: Scalar,
  public_key_x: Scalar,
  public_key_y: Scalar,
}

impl Default for SigningCircuit<Fq> {
  fn default() -> Self {
    Self {
      scalar: U256::ZERO,
      t_x: Fq::zero(),
      t_y: Fq::zero(),
      u_x: Fq::zero(),
      u_y: Fq::zero(),
      public_key_x: Fq::zero(),
      public_key_y: Fq::zero(),
    }
  }
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

impl CircuitTypes for SigningCircuit<Fq> {
  type CompressedProof = CompressedSNARK<E1, S1, S2>;
  type PublicParams = PublicParams<E1>;
}

impl SigningCircuit<Fq> {
  // pub fn build_circuit(hash: &[u8], signature: [u8; 65], public_key: <E1 as Engine>::GE);

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
    let z0_primary = [<E1 as Engine>::Scalar::ZERO];
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
    let z0_primary = [<E1 as Engine>::Scalar::ZERO];
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
    let z0_primary = [<E1 as Engine>::Scalar::ZERO];
    let z0_secondary = [<E2 as Engine>::Scalar::ZERO];

    let (_, vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params)?;
    let (res, _) = compressed_proof.verify(&vk, 1, &z0_primary, &z0_secondary)?;

    Ok(res)
  }
}

/// Signs a message using the private key, returns the signature (r, s)
pub fn sign(msg: Fq, priv_key: Fq) -> (Point, Fq) {
  // let mut rng = thread_rng();
  let n = U256::from_be_hex("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001");
  let g = Point::generator();

  let k = Fq::random(OsRng);
  let k_inv = k.invert();
  assert!(bool::from(k_inv.is_some()));
  let k_inv = k_inv.unwrap();

  let r: Point = g.mul(k).into();
  let (r_x, _, r_z) = r.jacobian_coordinates();
  let r_zinv = r_z.invert().unwrap();
  let r_zinv2 = r_zinv.square();
  let r_x = r_x * r_zinv2;
  let r_x = Fq::from_repr(
    U256::from_le_bytes(r_x.to_repr())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes()
      .into(),
  );
  assert!(bool::from(r_x.is_some()));
  let r_x = r_x.unwrap();

  let s = k_inv * (msg + priv_key * r_x);

  (r, s)
}

/// returns x coordinate of the point in affine coordinates
pub fn get_x_affine(point: Point) -> Fp {
  let (x, _, z) = point.jacobian_coordinates();
  let z_inv = z.invert().unwrap();
  let z_inv2 = z_inv.square();
  let x = x * z_inv2;
  x
}

/// returns y coordinate of the point in affine coordinates
pub fn get_y_affine(point: Point) -> Fp {
  let (_, y, z) = point.jacobian_coordinates();
  let z_inv = z.invert().unwrap();
  let z_inv3 = z_inv.square() * z_inv;
  let y = y * z_inv3;
  y
}

/// Gets the T and U points from R (output of message signature) and the message
pub fn get_points(r: Point, msg: Fq) -> (Point, Point) {
  let n = U256::from_be_hex("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001");

  let g = Point::generator();
  let (r_x, _, r_z) = r.jacobian_coordinates();
  let r_zinv = r_z.invert().unwrap();
  let r_zinv2 = r_zinv.square();
  let r_x = r_x * r_zinv2;
  let r_q = Fq::from_repr(
    U256::from_le_bytes(r_x.to_repr())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes()
      .into(),
  );
  assert!(bool::from(r_q.is_some()));
  let r_q = r_q.unwrap();

  let r_q_inv = r_q.invert();
  assert!(bool::from(r_q_inv.is_some()));
  let r_q_inv = r_q_inv.unwrap();

  let t: Point = r.mul(r_q_inv).into();
  let u: Point = g.mul(r_q_inv * msg).neg().into();

  (t, u)
}
