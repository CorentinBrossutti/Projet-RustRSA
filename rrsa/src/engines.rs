use crate::keys::Key;
use crate::messages::*;
use std::convert::TryInto;
use num_bigint::{BigUint, RandBigInt};

pub const PADSIZE_DEF: usize = 1;
pub const BSIZE_DEF: usize = 8;


pub trait Engine
{
    type EncryptionKey : Key;
    type DecryptionKey : Key;
    type MainKey : Key;

    fn generate(&self) -> Self::MainKey;
    fn run_crypt(&self, num: &mut BigUint, key: &Self::EncryptionKey);
    fn run_decrypt(&self, num: &mut BigUint, key: &Self::DecryptionKey);

    fn pad(&self, num: &mut BigUint, padsize: usize)
    {
        let bits: u32 = (padsize * 8).try_into().unwrap();

        *num *= BigUint::from(2u8).pow(bits);
        *num += rand::thread_rng().gen_biguint(bits.into());
    }

    fn unpad(&self, num: &mut BigUint, padsize: usize)
    {
        *num /= BigUint::from(2u8).pow((padsize * 8).try_into().unwrap());
    }

    fn encode(&self, num: &mut BigUint, key: &Self::EncryptionKey, padsize: usize)
    {
        self.pad(num, padsize);
        self.run_crypt(num, key);
    }

    fn decode(&self, num: &mut BigUint, key: &Self::DecryptionKey, padsize: usize)
    {
        self.run_decrypt(num, key);
        self.unpad(num, padsize);
    }

    fn encrypt(&self, message: &mut Message, key: &Self::EncryptionKey)
    {
        for part in message.parts.iter_mut()
        {
            self.encode(part, key, message.padsize);
        }
        message.encrypted = true;
        message.refresh_nval();
    }

    fn decrypt(&self, message: &mut Message, key: &Self::DecryptionKey)
    {
        for part in message.parts.iter_mut()
        {
            self.decode(part, key, message.padsize);
        }
        message.encrypted = false;
        message.refresh_nval();
    }
}