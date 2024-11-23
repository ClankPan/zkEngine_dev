//! Simulating a signing circuit
#![allow(non_snake_case)]

use crypto_bigint::{Encoding, U256};
use ff::{Field, PrimeField};
use halo2curves::{group::Group, CurveExt};
use nova::provider::{PallasEngine, VestaEngine};
use nova::traits::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ops::{Mul, Neg};
use std::time::Instant;
use zk_engine::precompiles::signing::{CircuitTypes, SigningCircuit};

use rand::rngs::OsRng;

type E1 = PallasEngine;
type E2 = VestaEngine;

type Fp1 = <E1 as Engine>::Base;
type Fq1 = <E1 as Engine>::Scalar;
type GE1 = <E1 as Engine>::GE;

type Fp2 = <E2 as Engine>::Base;
type Fq2 = <E2 as Engine>::Scalar;
type GE2 = <E2 as Engine>::GE;

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

  // The order of the scalar field
  let n = U256::from_be_hex("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001");

  let secret_key_hex = b"4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let secret_key: [u8; 32] = hex::decode(secret_key_hex).unwrap().try_into().unwrap();

  let msg = b"Hello, World!";
  let mut hasher = Sha256::new();
  hasher.update(msg);
  let digest = hasher.finalize();
  let digest: [u8; 32] = digest.as_slice().try_into().unwrap();

  let digest_elem = Fq1::from_repr(
    U256::from_le_bytes(digest.into())
      .checked_rem(&n)
      .unwrap()
      .to_le_bytes(),
  )
  .unwrap();

  let secret_key_elem = Fq1::from_repr(
    U256::from_le_bytes(secret_key.into())
      .checked_rem(&n)
      .unwrap()
      .to_le_bytes(),
  )
  .unwrap();

  // let digest_elem = Fq::from_repr(
  //   U256::from_le_bytes(digest.into())
  //     .checked_rem(&n)
  //     .unwrap()
  //     .to_le_bytes(),
  // )
  // .unwrap();

  // let secret_key_elem = Fq::from_repr(
  //   U256::from_le_bytes(secret_key.into())
  //     .checked_rem(&n)
  //     .unwrap()
  //     .to_le_bytes(),
  // );

  // if secret_key_elem.is_none().into() {
  //   panic!("Invalid secret key");
  // }

  // let secret_key_elem = secret_key_elem.unwrap();

  let g = GE1::generator();

  let public_key: GE1 = g.mul(secret_key_elem).into();

  let (r, s) = sign(digest_elem, secret_key_elem);

  let (t, u) = get_points(r, digest_elem);

  let (t_x, t_y) = (get_x_affine(t), get_y_affine(t));

  let lhs = t_y.square();
  let rhs = t_x.square() * t_x + Fp1::from(5u64);
  if (lhs != Fp1::ZERO) & (rhs != Fp1::from(5u64)) {
    // assert only for points other than (0, 0)
    assert_eq!(lhs, rhs, "(x,y) not on secp256k1");
  }

  let (u_x, u_y) = (get_x_affine(u), get_y_affine(u));
  let (pk_x, pk_y) = (get_x_affine(public_key), get_y_affine(public_key));

  /*   let tx_q = Fq::from_repr(
    U256::from_le_bytes(t_x.to_repr())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  )
  .unwrap();
  let ty_q = Fq::from_repr(
    U256::from_le_bytes(t_y.to_repr())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  )
  .unwrap();
  let ux_q = Fq::from_repr(
    U256::from_le_bytes(u_x.to_repr())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  )
  .unwrap();
  let uy_q = Fq::from_repr(
    U256::from_le_bytes(u_y.to_repr())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  )
  .unwrap();
  let pkx_q = Fq::from_repr(
    U256::from_le_bytes(pk_x.to_repr())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  )
  .unwrap();
  let pky_q = Fq::from_repr(
    U256::from_le_bytes(pk_y.to_repr())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  )
  .unwrap(); */

  let scalar = U256::from_le_bytes(s.to_repr());

  let circuit_primary: SigningCircuit<Fq2> =
    SigningCircuit::new(scalar, t_x, t_y, u_x, u_y, pk_x, pk_y);
  // Building circuit's public params
  let start = Instant::now();
  let pp: nova::PublicParams<VestaEngine> = circuit_primary.get_public_params().unwrap();
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

/// Signs a message using the private key, returns the signature (r, s)
pub fn sign(msg: Fq1, priv_key: Fq1) -> (GE1, Fq1) {
  // let mut rng = thread_rng();
  let n = U256::from_be_hex("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001");
  let g = GE1::generator();

  let k = Fq1::random(OsRng);
  let k_inv = k.invert();
  assert!(bool::from(k_inv.is_some()));
  let k_inv = k_inv.unwrap();

  let r: GE1 = g.mul(k).into();
  let (r_x, _, r_z) = r.jacobian_coordinates();
  let r_zinv = r_z.invert().unwrap();
  let r_zinv2 = r_zinv.square();
  let r_x = r_x * r_zinv2;
  let r_x = Fq1::from_repr(
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

/// Gets the T and U points from R (output of message signature) and the message
pub fn get_points(r: GE1, msg: Fq1) -> (GE1, GE1) {
  let n = U256::from_be_hex("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001");

  let g = GE1::generator();
  let (r_x, _, r_z) = r.jacobian_coordinates();
  let r_zinv = r_z.invert().unwrap();
  let r_zinv2 = r_zinv.square();
  let r_x = r_x * r_zinv2;
  let r_q = Fq1::from_repr(
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

  let t: GE1 = r.mul(r_q_inv).into();
  let u: GE1 = g.mul(r_q_inv * msg).neg().into();

  (t, u)
}

/// returns x coordinate of the point in affine coordinates
pub fn get_x_affine(point: GE1) -> Fp1 {
  let (x, _, z) = point.jacobian_coordinates();
  let z_inv = z.invert().unwrap();
  let z_inv2 = z_inv.square();
  let x = x * z_inv2;
  x
}

/// returns y coordinate of the point in affine coordinates
pub fn get_y_affine(point: GE1) -> Fp1 {
  let (_, y, z) = point.jacobian_coordinates();
  let z_inv = z.invert().unwrap();
  let z_inv3 = z_inv.square() * z_inv;
  let y = y * z_inv3;
  y
}
