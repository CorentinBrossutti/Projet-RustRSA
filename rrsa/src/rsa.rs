use crate::{engines::Engine, maths, keys::*};
use num_bigint::ToBigInt;
use crossbeam::channel;
use num_traits::Signed;
use std::thread;

const PRIME_SIZEB: u16 = 64;
const GEN_THREADS: u8 = 2;

pub struct Rsa;

impl Engine for Rsa
{
    type EncryptionKey = KeyPair<NumKey, NumKey>;
    type DecryptionKey = KeyPair<NumKey, NumKey>;
    type MainKey = KeyPair<KeyPair<NumKey, NumKey>, KeyPair<NumKey, NumKey>>;

    fn generate(&self) -> Self::MainKey {
        let (g_tx, g_rx) = channel::unbounded();
        let (f_tx, f_rx) = channel::unbounded();
        let (g_halt_tx, g_halt_rx) = channel::unbounded();
        let mut handle = None;

        for _ in 0..GEN_THREADS
        {
            let g_tx_c = g_tx.clone();
            let g_rx_c = g_rx.clone();

            let f_tx_c = f_tx.clone();
            let f_rx_c = f_rx.clone();

            let g_halt_tx_c = g_halt_tx.clone();
            let g_halt_rx_c = g_halt_rx.clone();

            thread::spawn(move || {
                while g_halt_rx_c.try_recv().is_err()
                {
                    g_tx_c.send(maths::rand_primelike(PRIME_SIZEB.into())).expect("Rsa.generate : erreur dans la génération.");
                }
            });

            handle = Some(thread::spawn(move || {
                let mut temp;
                while f_rx_c.len() < 2
                {
                    temp = g_rx_c.recv().unwrap();
                    if maths::isprime(&temp)
                    {
                        f_tx_c.send(temp).expect("Rsa.generate : erreur dans le remplissage.");
                    }
                }
                g_halt_tx_c.send(()).expect("Rsa.generate : erreur dans le signalement.");
            }));
        }

        handle.unwrap().join().expect("Rsa.generate : erreur dans la fusion.");
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
            KeyPair::from(NumKey::from(&n), NumKey::from(&e)), 
            KeyPair::from(NumKey::from(&n), NumKey::from(&d.to_biguint().unwrap())))
    }

    fn run_crypt(&self, num: &mut num_bigint::BigUint, key: &Self::EncryptionKey) {
        *num = maths::fmodpow(num, &key.1, &key.0);
    }

    fn run_decrypt(&self, num: &mut num_bigint::BigUint, key: &Self::DecryptionKey) {
        *num = maths::fmodpow(num, &key.1, &key.0)
    }
}
