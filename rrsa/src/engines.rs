use crate::{keys::*, maths, messages::Message};
use std::{convert::TryInto, sync::{Arc, atomic}, thread};
use crossbeam::channel;
use num_bigint::{BigUint, RandBigInt, ToBigInt};
use num_traits::Signed;

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


const PRIME_SIZEB: u16 = 64;
const GEN_THREADS: u8 = 2;

pub struct Rsa;

impl Engine for Rsa
{
    type EncryptionKey = KeyPair<NumKey, NumKey>;
    type DecryptionKey = KeyPair<NumKey, NumKey>;
    type MainKey = KeyPair<Self::EncryptionKey, Self::DecryptionKey>;

    fn generate(&self) -> Self::MainKey {
        let (g_tx, g_rx) = channel::unbounded();
        let (f_tx, f_rx) = channel::unbounded();

        let working = Arc::new(atomic::AtomicBool::new(true));

        for _ in 0..GEN_THREADS
        {
            let g_tx_c = g_tx.clone();
            let g_rx_c = g_rx.clone();

            let f_tx_c = f_tx.clone();
            let f_rx_c = f_rx.clone();

            let (working_g_c, working_f_c) = (working.clone(), working.clone());

            thread::spawn(move || {
                while working_g_c.load(atomic::Ordering::Relaxed)
                {
                    g_tx_c.send(maths::rand_primelike(PRIME_SIZEB.into())).expect("Rsa.generate : erreur dans la génération.");
                }
            });

            thread::spawn(move || {
                let mut temp;
                while working_f_c.load(atomic::Ordering::Relaxed)
                {
                    temp = g_rx_c.recv().unwrap();
                    if maths::isprime(&temp)
                    {
                        f_tx_c.send(temp).expect("Rsa.generate : erreur dans le remplissage.");
                    }
                    if f_rx_c.len() >= 2
                    {
                        working_f_c.store(false, atomic::Ordering::Relaxed);
                    }
                }
            });
        }

        let (p, q) = (f_rx.recv().unwrap(), f_rx.recv().unwrap());
        let n = &p * &q;
        let ind = (p - 1u8) * (q - 1u8);
        let e = maths::expcode(&ind).unwrap();
        let mut d = maths::euclide(&e.to_bigint().unwrap(), &ind.to_bigint().unwrap());

        if d.is_negative()
        {
            d += ind.to_bigint().unwrap();
        }

        KeyPair::from(
            KeyPair::from(NumKey::from(n.clone()), NumKey::from(e)), 
            KeyPair::from(NumKey::from(n), NumKey::from(d.to_biguint().unwrap())))
    }

    fn run_crypt(&self, num: &mut num_bigint::BigUint, key: &Self::EncryptionKey) {
        *num = maths::fmodpow(num, &key.1, &key.0);
    }

    fn run_decrypt(&self, num: &mut num_bigint::BigUint, key: &Self::DecryptionKey) {
        *num = maths::fmodpow(num, &key.1, &key.0)
    }
}