//! Simulating a signing circuit
#![allow(non_snake_case)]

use crypto_bigint::{Encoding, U256};
use ff::{Field, PrimeField};
use halo2curves::group::Curve;
use nova::provider::{Secp256k1Engine, Secq256k1Engine};
use nova::traits::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ops::{Mul, Neg};
use std::time::Instant;
use zk_engine::precompiles::signing::{
  compress_proof, get_public_params, prove, verify, verify_compressed, CircuitTypes, SigningCircuit,
};

use rand::rngs::OsRng;

type E1 = Secp256k1Engine;

type Fp = <E1 as Engine>::Base;
type Fq = <E1 as Engine>::Scalar;
type GE = <E1 as Engine>::GE;

#[derive(Serialize)]
struct SendDataBody {
  data: String,
  snark: <SigningCircuit as CircuitTypes>::CompressedProof,
  did: String,
}
type PP = <SigningCircuit as CircuitTypes>::PublicParams;
fn main() -> anyhow::Result<()> {
  println!("=========================================================");
  println!("Nova-based Signing example");
  println!("=========================================================");

  // The order of the scalar field
  let n = U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

  let secret_key_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let secret_key: [u8; 32] = hex::decode(secret_key_hex).unwrap().try_into().unwrap();

  let msg = b"Hello, World!";
  let mut hasher = Sha256::new();
  hasher.update(msg);
  let digest = hasher.finalize();
  let digest: [u8; 32] = digest.as_slice().try_into().unwrap();

  // Convert the digest and secret key to field elements
  let digest_elem = Fq::from_repr(
    U256::from_le_bytes(digest.into())
      .checked_rem(&n)
      .unwrap()
      .to_le_bytes(),
  )
  .unwrap();

  let secret_key_elem = Fq::from_repr(
    U256::from_le_bytes(secret_key.into())
      .checked_rem(&n)
      .unwrap()
      .to_le_bytes(),
  )
  .unwrap();

  let g = GE::generator();

  let public_key: GE = g.mul(secret_key_elem).into();

  let (r, s) = sign(digest_elem, secret_key_elem);

  let (t, u) = get_points(r, digest_elem);

  let t_affine = t.to_affine();
  let u_affine = u.to_affine();
  let pk_affine = public_key.to_affine();

  let scalar = U256::from_le_bytes(s.to_bytes());

  let circuit_primary: SigningCircuit<Fp> = SigningCircuit::new(
    scalar,
    t_affine.x,
    t_affine.y,
    u_affine.x,
    u_affine.y,
    pk_affine.x,
    pk_affine.y,
  );

  // Building circuit's public params
  let start = Instant::now();
  let pp: nova::PublicParams<Secq256k1Engine> = get_public_params(&circuit_primary)?;
  println!("Building public params took {:?}", start.elapsed());

  //
  // Serializing for sending
  //

  let pp_ser = serde_json::to_string(&pp).unwrap();

  //
  // Deserializing after reception
  //

  let public_params_deser: PP = serde_json::from_str(&pp_ser).unwrap();

  //
  // produce a recursive SNARK
  //

  println!("Generating a RecursiveSNARK...");
  let start = Instant::now();
  let recursive_snark = prove(&circuit_primary, &public_params_deser).unwrap();

  println!("RecursiveSNARK::proving took {:?} ", start.elapsed());

  //
  // verify the recursive SNARK
  //

  let start = Instant::now();

  println!("Verifying a RecursiveSNARK...");
  let res = verify(&public_params_deser, &recursive_snark);
  println!(
    "RecursiveSNARK::verify: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
  );
  assert!(res.is_ok());
  let output = res.unwrap();
  println!("Output: {:?}", output);

  //
  // produce a compressed SNARK
  //

  println!("Compressing the RecursiveSNARK...");
  let start = Instant::now();

  let compressed_proof = compress_proof(&public_params_deser, &recursive_snark).unwrap();
  println!("CompressedSNARK::prove took {:?} ", start.elapsed());

  //
  // verify the compressed SNARK
  //

  println!("Verifying a CompressedSNARK...");
  let start = Instant::now();
  let res = verify_compressed(&public_params_deser, &compressed_proof);
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

  Ok(())
}

/// Signs a message using the private key, returns the signature (r, s)
fn sign(msg: Fq, priv_key: Fq) -> (GE, Fq) {
  let n = U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  let g = GE::generator();

  let k = Fq::random(OsRng);
  let k_inv = k.invert();
  assert!(bool::from(k_inv.is_some()));
  let k_inv = k_inv.unwrap();

  let r: GE = g.mul(k).into();
  let r_affine = r.to_affine();
  let r_x = Fq::from_repr(
    U256::from_le_bytes(r_affine.x.to_bytes())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  );
  assert!(bool::from(r_x.is_some()));
  let r_x = r_x.unwrap();

  let s = k_inv * (msg + priv_key * r_x);

  (r, s)
}
/// Gets the T and U points from R (output of message signature) and the message
fn get_points(r: GE, msg: Fq) -> (GE, GE) {
  let n = U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

  let g = GE::generator();

  let r_affine = r.to_affine();

  let r_q = Fq::from_repr(
    U256::from_le_bytes(r_affine.x.to_bytes())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  );
  assert!(bool::from(r_q.is_some()));
  let r_q = r_q.unwrap();

  let r_q_inv = r_q.invert();
  assert!(bool::from(r_q_inv.is_some()));
  let r_q_inv = r_q_inv.unwrap();

  let t: GE = r.mul(r_q_inv).into();
  let u: GE = g.mul(r_q_inv * msg).neg().into();

  (t, u)
}
