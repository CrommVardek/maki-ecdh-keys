use k256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey as PK};
use ring::agreement::agree_ephemeral;
use ring::agreement::Algorithm;
use ring::agreement::EphemeralPrivateKey;
use ring::agreement::PublicKey;
use ring::agreement::UnparsedPublicKey;
use ring::agreement::ECDH_P256;
use ring::agreement::ECDH_P384;
use ring::agreement::X25519;
use ring::error::Unspecified;
use ring::rand::SystemRandom;

use sha2::Sha256;

use hex_literal::hex as hex_macro;
use rand_core::OsRng;

use hex;

pub fn generate_ecdh_key_pair() -> Result<(), ring::error::Unspecified> {
    // Use a rand::SystemRandom as the source of entropy
    let rng = SystemRandom::new();

    // Select a key agreement algorithm. All agreement algorithms follow the same flow
    let alg: &Algorithm = &ECDH_P384;

    // Generate a private key and public key
    let my_private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(alg, &rng)?;
    let my_public_key: PublicKey = my_private_key.compute_public_key()?;

    // The EphemeralPrivateKey type doesn't allow us to directly access the private key as designed
    println!("my_public_key = {}", hex::encode(my_public_key.as_ref()));
    Ok(())
}

pub fn generate_shared_key_k256() {
    let a = EphemeralSecret::random(&mut OsRng);
    let A = EncodedPoint::from(a.public_key());

    let b = EphemeralSecret::random(&mut OsRng);
    let B = EncodedPoint::from(b.public_key());

    let bob_public = PK::from_sec1_bytes(B.as_ref()).expect("Bob's public key invalid");

    let alice_public = PK::from_sec1_bytes(A.as_ref()).expect("Alice's public key invalid");

    let Abytes = A.as_ref();
    println!("\nAlice public key {:x?}", hex::encode(Abytes));

    let Bbytes = B.as_ref();
    println!("\nBob public key {:x?}", hex::encode(Bbytes));

    let Abytes = A.as_ref();
    println!("\nAlice public key {:x?}", hex::encode(Abytes));

    let Bbytes = B.as_ref();
    println!("\nBob public key {:x?}", hex::encode(Bbytes));
    let mut okm = [0u8; 42];

    let alice_shared = a.diffie_hellman(&bob_public);
    let bob_shared = b.diffie_hellman(&alice_public);

    let salt = hex_macro!("000102030405060708090a0b0c");
    let info = hex_macro!("f0f1f2f3f4f5f6f7f8f9");

    let mut okm = [0u8; 42];
    let shared1 = alice_shared
        .extract::<Sha256>(Some(&salt[..]))
        .expand(&info, &mut okm);
    println!("\nAlice shared secret key {:x?}", hex::encode(okm));

    let mut okm2 = [0u8; 42];
    let shared2 = bob_shared
        .extract::<Sha256>(Some(&salt[..]))
        .expand(&info, &mut okm2);
    println!("\nBob shared secret key {:x?}", hex::encode(okm2));

    if okm == okm2 {
        println!("\nKeys are the same")
    }
}
