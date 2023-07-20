mod ecdh_key_gen;

fn main() {
    ecdh_key_gen::generate_ecdh_key_pair();
    ecdh_key_gen::generate_shared_key_k256();
}



