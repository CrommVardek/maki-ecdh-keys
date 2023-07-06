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

pub fn generateEcdhKeyPair() {
    // Use a rand::SystemRandom as the source of entropy
    let rng = SystemRandom::new();

    // Select a key agreement algorithm. All agreement algorithms follow the same flow
    let alg: &Algorithm = &X25519;

    // Generate a private key and public key
    let my_private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(alg, &rng)?;
    let my_public_key: PublicKey = my_private_key.compute_public_key()?;

    // The EphemeralPrivateKey type doesn't allow us to directly access the private key as designed
    println!("my_public_key = {}", hex::encode(my_public_key.as_ref()));
}
