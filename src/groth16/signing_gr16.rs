//! Simulating a signing circuit
use bellperson::{
  gadgets::{
    boolean::{AllocatedBit, Boolean},
    multipack,
    sha256::sha256,
  },
  groth16, Circuit, ConstraintSystem, SynthesisError,
};
use blstrs::Bls12;
use ff::PrimeField;
use pairing::Engine;
use rand::rngs::OsRng;
use secp256k1::{
  ecdsa::{serialized_signature, RecoverableSignature, RecoveryId},
  Message, PublicKey, Secp256k1, SecretKey,
};
use sha2::{Digest, Sha256};

/// Set fields to `None` when we are verifying a proof (and do not have the witness data).
struct MyCircuit {
  /// hash that was signed
  hash: Option<[u8; 32]>,
  /// 64-bytes signature, prepended by recovery id, used to recover public key
  signature: Option<[u8; 65]>,
  /// public input: the signer's public key
  public_key: Option<[u8; 33]>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
  fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
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

    Ok(())
  }
}

// Create parameters for our circuit. In a production deployment these would
// be generated securely using a multiparty computation.
fn main() {
  let params = {
    let c = MyCircuit {
      hash: None,
      signature: None,
      public_key: None,
    };
    groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
  };

  // Prepare the verification key (for proof verification).
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
  assert!(groth16::verify_proof(&pvk, &proof, &inputs).unwrap());
}
