//! Simulating a signing circuit
use bellperson::groth16;
use blstrs::Bls12;
use bp_ecdsa::core::num::AllocatedNum;
use bp_ecdsa::core::Circuit;
use bp_ecdsa::core::{ConstraintSystem, SynthesisError};
use ff::{PrimeField, PrimeFieldBits};
use halo2curves::{
  secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine},
  serde::{endian::EndianRepr, SerdeObject},
};
use pairing::Engine;
use rand::rngs::OsRng;

use crypto_bigint::U256;

use base64::{display::Base64Display, engine::general_purpose::STANDARD};
use bp_ecdsa::{curve::AllocatedAffinePoint, ecdsa::verify_eff};
use sha2::{Digest, Sha256};
use std::ops::Mul;

struct CurvePoint {
  x: Option<Fp>,
  y: Option<Fp>,
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

impl Circuit<Fp> for MyCircuit {
  fn synthesize<CS: ConstraintSystem<Fp>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
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
    );

    /*let secret_key_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let secret_key = hex::decode(secret_key_hex).unwrap();

        let sk = Fq::from_bytes(&secret_key.try_into().unwrap()).unwrap();

        let g = Secp256k1Affine::generator();

        let pk: Secp256k1Affine = g.mul(sk).into();
        let hash = if let Some(hash) = self.hash {
          hash
        } else {
          [0u8; 32]
        };

        let (recoveryId, signature): (RecoveryId, [u8; 64]) = if let Some(signature) = self.signature {
          (
            TryFrom::try_from(signature[0] as i32).unwrap(),
            signature[1..].try_into().unwrap(),
          )
        } else {
          (RecoveryId::Zero, [0u8; 64])
        };

        let public_key = if let Some(public_key) = self.public_key {
          public_key
        } else {
          [0u8; 33]
        };

        // TODO: Implement signature circuit
        // Currently is simulated

        let public_key_bits = public_key
          .iter()
          .map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
          .flatten()
          .map(|b| Some(b))
          .collect::<Vec<_>>();

        // witness the bits of the public key
        let public_key_bits = public_key_bits
          .into_iter()
          .enumerate()
          .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("public key bit {}", i)), b))
          .map(|b| b.map(Boolean::from))
          .collect::<Result<Vec<_>, _>>()?;

        let rec_sig = RecoverableSignature::from_compact(&signature, recoveryId).unwrap();
        let message = Message::from_digest_slice(&hash).unwrap();

        let signer_pk = rec_sig.recover(&message).unwrap().serialize();

        let signer_pk_bits = signer_pk
          .iter()
          .map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
          .flatten()
          .map(|b| Boolean::constant(b))
          .collect::<Vec<_>>();

        // witness the bits of the expected public key

        // Expose the vector of 32 boolean variables as compact public inputs.
        multipack::pack_into_inputs(cs.namespace(|| "pack expected public key"), &signer_pk_bits);

        // Test equality of the two public keys
        for (i, (a, b)) in public_key_bits
          .iter()
          .zip(signer_pk_bits.iter())
          .enumerate()
        {
          Boolean::enforce_equal(cs.namespace(|| format!("public key bit {}", i)), a, b)?;
        }
    */
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
  println!("x: {:?}", pk.x.to_bytes());
  println!("y: {:?}", pk.y.to_bytes());

  // Prepare the verification key (for proof verification).
  /* let params = {
    let c = MyCircuit {
      hash: None,
      signature: None,
      public_key: None,
    };
    groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
  };
    let pvk = groth16::prepare_verifying_key(&params.vk);

  // Pick a hash and public key, and sign the hash.

  let secp = Secp256k1::new();
  let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
  let message = b"hello world";
  let hash = Sha256::digest(message);
  let message = Message::from_digest_slice(&hash).unwrap();
  let signature = secp.sign_ecdsa_recoverable(&message, &secret_key);

  let serialized_signature = signature.serialize_compact();
  let mut signature_slice = [0u8; 65];
  signature_slice[0] = Into::<i32>::into(serialized_signature.0) as u8;
  signature_slice[1..].copy_from_slice(&serialized_signature.1);

  // Create an instance of our circuit (with the preimage as a witness).
  let c = MyCircuit {
    hash: Some(hash.into()),
    signature: Some(signature_slice),
    public_key: Some(public_key.serialize()),
  };

  // Create a Groth16 proof with our parameters.
  let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

  // Pack the public key as inputs for proof verification.
  let public_key_bits = public_key
    .serialize()
    .iter()
    .map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
    .flatten()
    .collect::<Vec<_>>();
  let inputs = multipack::compute_multipacking::<blstrs::Scalar>(&public_key_bits);
  // Check the proof!
  assert!(groth16::verify_proof(&pvk, &proof, &inputs).unwrap()); */
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
