//! Simulating a signing circuit
#![allow(non_snake_case)]

use crypto_bigint::{Encoding, U256};
use ff::PrimeField;
use halo2curves::group::Group;
use nova::provider::PallasEngine;
use nova::traits::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ops::Mul;
use std::time::Instant;
use zk_engine::precompiles::signing::{
  get_points, get_x_affine, get_y_affine, sign, CircuitTypes, SigningCircuit,
};

type E1 = nova::provider::PallasEngine;

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
fn main() {
  println!("=========================================================");
  println!("Nova-based Signing example");
  println!("=========================================================");

  // The order of the scalar field
  let n = U256::from_be_hex("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001");

  let secret_key_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let secret_key: [u8; 32] = hex::decode(secret_key_hex).unwrap().try_into().unwrap();

  let msg = b"Hello, World!";
  let mut hasher = Sha256::new();
  hasher.update(msg);
  let digest = hasher.finalize();
  let digest: [u8; 32] = digest.as_slice().try_into().unwrap();

  let digest_elem = Fq::from_repr(
    U256::from_le_bytes(digest.into())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  )
  .unwrap();

  let secret_key_elem = Fq::from_repr(
    U256::from_le_bytes(secret_key.into())
      .add_mod(&U256::ZERO, &n)
      .to_le_bytes(),
  );

  if secret_key_elem.is_none().into() {
    panic!("Invalid secret key");
  }

  let secret_key_elem = secret_key_elem.unwrap();

  let g = <PallasEngine as Engine>::GE::generator();

  let public_key: <PallasEngine as Engine>::GE = g.mul(secret_key_elem).into();

  let (r, s) = sign(digest_elem, secret_key_elem);

  let (t, u) = get_points(r, digest_elem);

  let (t_x, t_y) = (get_x_affine(t), get_y_affine(t));
  let (u_x, u_y) = (get_x_affine(u), get_y_affine(u));
  let (pk_x, pk_y) = (get_x_affine(public_key), get_y_affine(public_key));

  let tx_q = Fq::from_repr(
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
  .unwrap();

  let scalar = U256::from_le_bytes(s.to_repr());

  let circuit_primary: SigningCircuit<Fq> =
    SigningCircuit::new(scalar, tx_q, ty_q, ux_q, uy_q, pkx_q, pky_q);
  // Building circuit's public params
  let start = Instant::now();
  let pp: nova::PublicParams<nova::provider::PallasEngine> =
    circuit_primary.get_public_params().unwrap();
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
