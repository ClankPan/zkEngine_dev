//! Simulating a signing circuit
use bellperson::groth16;
use blstrs::{Bls12, Scalar as Fr};
use bp_ecdsa::core::boolean::Boolean;
use bp_ecdsa::core::num::AllocatedNum;
use bp_ecdsa::core::Circuit;
use bp_ecdsa::core::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldBits};
use halo2curves::hash_to_curve::hash_to_curve;
use halo2curves::CurveExt;
// use halo2curves::{
//   bn256::{Fq, Fr, Bn256},
//   serde::{Repr, SerdeObject},
// };
use pairing::Engine;
use rand::rngs::OsRng;

use crypto_bigint::{Encoding, Random, Zero, U256};

use base64::{display::Base64Display, engine::general_purpose::STANDARD};
use bp_ecdsa::{curve::AllocatedAffinePoint, ecdsa::verify_eff};
use sha2::{Digest, Sha256};
use std::ops::{Mul, Neg};

struct CurvePoint {
  x: Option<Fr>,
  y: Option<Fr>,
}

/// Set fields to `None` when we are verifying a proof (and do not have the witness data).
struct MyCircuit {
  scalar: U256,
  /// hash that was signed
  t: Option<Secp256k1Affine>,
  /// 64-bytes signature, prepended by recovery id, used to recover public key
  u: Option<Secp256k1Affine>,
  /// public input: the signer's public key
  public_key: Option<Secp256k1Affine>,
}

impl Circuit<Fr> for MyCircuit {
  fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
    let t = if let Some(t) = self.t {
      CurvePoint {
        x: Some(t.x),
        y: Some(t.y),
      }
    } else {
      CurvePoint { x: None, y: None }
    };

    let u = if let Some(u) = self.u {
      CurvePoint {
        x: Some(u.x),
        y: Some(u.y),
      }
    } else {
      CurvePoint { x: None, y: None }
    };

    let public_key = if let Some(public_key) = self.public_key {
      CurvePoint {
        x: Some(public_key.x),
        y: Some(public_key.y),
      }
    } else {
      CurvePoint { x: None, y: None }
    };

    let t_alloc = alloc_affine_point(&mut cs.namespace(|| "alloc t"), t.x, t.y)?;

    let u_alloc = alloc_affine_point(&mut cs.namespace(|| "alloc u"), u.x, u.y)?;

    let public_key_alloc = alloc_affine_point(
      &mut cs.namespace(|| "alloc public key"),
      public_key.x,
      public_key.y,
    )?;

    let out = verify_eff(
      &mut cs.namespace(|| "verify"),
      self.scalar,
      t_alloc,
      u_alloc,
      public_key_alloc,
    )
    .unwrap();

    let _ = Boolean::enforce_equal(cs, &out, &Boolean::Constant(true));

    Ok(())
  }
}

// Create parameters for our circuit. In a production deployment these would
// be generated securely using a multiparty computation.
fn main() {
  let secret_key_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let secret_key = hex::decode(secret_key_hex).unwrap();

  // convert secret_key to little endian
  let sk_le = secret_key.iter().rev().fold(Vec::new(), |mut acc, &x| {
    acc.push(x);
    acc
  });

  let sk = Fq::from_bytes(&sk_le.try_into().unwrap()).unwrap();

  let g = Secp256k1Affine::generator();

  let pk: Secp256k1Affine = g.mul(sk).into();

  let pk_ser = pk.to_raw_bytes();

  let value = Base64Display::new(&pk_ser, &STANDARD);
  println!("Public key: {:?}", format!("base64: {}", value));
  println!("x: {:?}", pk.x.to_bytes().reverse());
  println!("y: {:?}", pk.y.to_bytes().reverse());

  let message = "Hello world!";
  let hash: [u8; 32] = Sha256::digest(message.as_bytes()).try_into().unwrap();
  let hash_le: [u8; 32] = hash
    .iter()
    .rev()
    .copied()
    .collect::<Vec<u8>>()
    .try_into()
    .unwrap();
  let msg = Fq::from_repr(hash.into()).unwrap();

  let (r, s) = sign(msg, sk);

  let (t, u) = get_points(r, msg);

  // initialize params with dummy circuit
  let params = {
    let circuit = MyCircuit {
      scalar: U256::ZERO,
      t: None,
      u: None,
      public_key: None,
    };
    groth16::generate_random_parameters::<Bls12, _, _>(circuit, &mut OsRng).unwrap()
  };
}

fn alloc_affine_point<CS, F>(
  cs: &mut CS,
  x: Option<F>,
  y: Option<F>,
) -> Result<AllocatedAffinePoint<F>, SynthesisError>
where
  CS: ConstraintSystem<F>,
  F: PrimeField + PrimeFieldBits,
{
  let x_val = x.ok_or(SynthesisError::AssignmentMissing)?;
  let y_val = y.ok_or(SynthesisError::AssignmentMissing)?;

  // Check (x, y) on secp256k1
  let lhs = y_val.square();
  let rhs = x_val.square() * x_val + F::from(7u64);
  if (lhs != F::ZERO) & (rhs != F::from(7u64)) {
    // assert only for points other than (0, 0)
    assert_eq!(lhs, rhs, "(x,y) not on secp256k1");
  }

  let x_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "alloc x"), || Ok(x_val))?;
  let y_alloc = AllocatedNum::alloc(&mut cs.namespace(|| "alloc y"), || Ok(y_val))?;

  Ok(AllocatedAffinePoint {
    x: x_alloc,
    y: y_alloc,
  })
}

/// Signs a message using the private key, returns the signature (r, s)
fn sign(msg: Fq, priv_key: Fq) -> (Secp256k1Affine, Fq) {
  // let mut rng = thread_rng();
  let n = U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  let g = Secp256k1Affine::generator();

  let k = Fq::random(OsRng);
  let k_inv = k.invert();
  assert!(bool::from(k_inv.is_some()));
  let k_inv = k_inv.unwrap();

  let r: Secp256k1Affine = g.mul(k).into();
  let r_x = Fq::from_repr(
    U256::from_le_bytes(r.x.to_bytes())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes()
      .into(),
  );
  assert!(bool::from(r_x.is_some()));
  let r_x = r_x.unwrap();

  let s = k_inv * (msg + priv_key * r_x);

  (r, s)
}

/// Gets the T and U points from R (output of message signature) and the message
fn get_points(r: Secp256k1Affine, msg: Fq) -> (Secp256k1Affine, Secp256k1Affine) {
  let n = U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

  let g = Secp256k1Affine::generator();

  let r_q = Fq::from_repr(
    U256::from_le_bytes(r.x.to_bytes())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes()
      .into(),
  );
  assert!(bool::from(r_q.is_some()));
  let r_q = r_q.unwrap();

  let r_q_inv = r_q.invert();
  assert!(bool::from(r_q_inv.is_some()));
  let r_q_inv = r_q_inv.unwrap();

  let t: Secp256k1Affine = r.mul(r_q_inv).into();
  let u: Secp256k1Affine = g.mul(r_q_inv * msg).neg().into();

  (t, u)
}
