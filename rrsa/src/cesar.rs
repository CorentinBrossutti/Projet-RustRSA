use num_bigint::RandBigInt;

use crate::{engines::Engine, maths::*, keys::*};


pub struct Cesar;

impl Engine for Cesar
{
    type EncryptionKey = NumKey;
    type DecryptionKey = NumKey;
    type MainKey = NumKey;

    fn generate(&self) -> Self::MainKey {
        NumKey::from(rand::thread_rng().gen_biguint(16))
    }

    fn run_crypt(&self, num: &mut num_bigint::BigUint, key: &Self::EncryptionKey) {
        *num += &key.value;
    }

    fn run_decrypt(&self, num: &mut num_bigint::BigUint, key: &Self::DecryptionKey) {
        *num -= &key.value;
    }
}