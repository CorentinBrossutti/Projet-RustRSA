use crate::{engines::Engine, maths::*, keys::*};


pub struct Rsa;

impl Engine for Rsa
{
    type EncryptionKey = KeyPair<NumKey, NumKey>;
    type DecryptionKey = KeyPair<NumKey, NumKey>;
    type MainKey = KeyPair<KeyPair<NumKey, NumKey>, KeyPair<NumKey, NumKey>>;

    fn generate(&self) -> Self::MainKey {
        todo!()
    }

    fn run_crypt(&self, num: &mut num_bigint::BigUint, key: &Self::EncryptionKey) {
        *num = fmodpow(num, &key.1, &key.0);
    }

    fn run_decrypt(&self, num: &mut num_bigint::BigUint, key: &Self::DecryptionKey) {
        *num = fmodpow(num, &key.1, &key.0)
    }
}
