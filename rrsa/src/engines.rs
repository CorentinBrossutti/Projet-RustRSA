use crate::{keys::*, maths, messages::Message};
use std::{sync::{Arc, atomic}, thread};
use crossbeam::channel;
use num_bigint::{BigUint, RandBigInt, ToBigInt};
use num_traits::Signed;


/// Taille par défaut du padding (nonce) à appliquer aux nombres à chiffrer. Peut changer en fonction du message. En octets.
pub const PADSIZE_DEF: u32 = 1;
/// Taille de bloc par défaut pour découper les messages trop longs, en octets. Peut changer en fonction du message.
pub const BSIZE_DEF: u32 = 64;

/// Un `Engine` est un moteur cryptographique disposant de certaines méthodes communes :
/// La méthode `pad` en est un exemple. Certaines fonctions sont toutefois non définies et doivent être implémentées au cas par cas.
/// C'est le cas par exemple des méthodes `generate`, `run_crypt`, etc
pub trait Engine
{
    /// Type (doit implémenter le trait `Key`) de la clé de chiffrement.
    type EncryptionKey : Key;
    /// Type (doit implémenter le trait `Key`) de la clé de chiffrement.
    type DecryptionKey : Key;
    /// Type de clé principale, celle générée. Pour RSA, il s'agit d'une paire composée de la clé de chiffrement, et de celle de déchiffrement.
    /// Pour un chiffrement césar par exemple, il s'agit d'une clé numérique, qui est en fait la même que la clé de chiffrement / déchiffrement
    type MainKey : Key;

    /// Génère une clé principale. Les paramètres peuvent ou non être pris en compte selon l'implémentation exacte.
    /// `sz_b` est la taille en octets de la clé à générer
    /// `n_threads` est le nombre de threads à utiliser pour la génération.
    fn generate(&self, sz_b: u64, n_threads: u8) -> Self::MainKey;
    /// Génère une clé principale avec des options par défaut.
    fn gen_def(&self) -> Self::MainKey;
    /// Chiffre un nombre avec une clé de chiffrement donnée.
    fn run_crypt(&self, num: &mut BigUint, key: &Self::EncryptionKey);
    /// Déchiffre un nombre avec une clé de déchiffrement donnée.
    fn run_decrypt(&self, num: &mut BigUint, key: &Self::DecryptionKey);

    /// Ajoute un nonce (padding) d'une taille donnée `padsize` en octets à un nombre.
    fn pad(&self, num: &mut BigUint, padsize: u32)
    {
        let bits: u32 = padsize * 8;

        *num *= BigUint::from(2u8).pow(bits);
        *num += rand::thread_rng().gen_biguint(bits.into());
    }

    /// Retire le nonce (padding) d'un nombre : retire en fait les derniers `padsize` octets.
    fn unpad(&self, num: &mut BigUint, padsize: u32)
    {
        *num /= BigUint::from(2u8).pow(padsize * 8);
    }

    /// Ajoute un nonce et chiffre un nombre.
    fn encode(&self, num: &mut BigUint, key: &Self::EncryptionKey, padsize: u32)
    {
        self.pad(num, padsize);
        self.run_crypt(num, key);
    }

    /// Déchiffre un nombre et lui retire son nonce.
    fn decode(&self, num: &mut BigUint, key: &Self::DecryptionKey, padsize: u32)
    {
        self.run_decrypt(num, key);
        self.unpad(num, padsize);
    }

    /// Chiffre un message avec une clé de chiffrement donnée.
    fn encrypt(&self, message: &mut Message, key: &Self::EncryptionKey)
    {
        for part in message.parts.iter_mut()
        {
            self.encode(part, key, message.padsize);
        }
        message.encrypted = true;
        message.refresh_nval();
    }

    /// Déchiffre un message avec une clé de déchiffrement donnée.
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


/// Implémentation d'un moteur de chiffrement pour un codage césar
/// Une seule clé numérique aléatoire joue le rôle de clé de chiffrement / principale / déchiffrement.
pub struct Cesar;

impl Engine for Cesar
{
    type EncryptionKey = NumKey;
    type DecryptionKey = NumKey;
    type MainKey = NumKey;

    fn generate(&self, sz_b: u64, _: u8) -> Self::MainKey {
        NumKey::from(rand::thread_rng().gen_biguint(sz_b * 8))
    }

    fn gen_def(&self) -> Self::MainKey 
    {
        self.generate(8, 0)
    }

    fn run_crypt(&self, num: &mut BigUint, key: &Self::EncryptionKey) {
        *num += &key.value;
    }

    fn run_decrypt(&self, num: &mut BigUint, key: &Self::DecryptionKey) {
        *num -= &key.value;
    }
}


/// Taille par défaut des entiers premiers (p et q) à générer pour RSA. Pour du RSA-2048 (par défaut), on génère 128 octets.
pub const RSA_DEF_PRIME_SIZEB: u64 = 128;
/// Nombre de threads par défaut pour la génération RSA. Ils ne sont utilisés que pour la vérification, très consommatrice en temps processeur.
pub const RSA_DEF_GEN_THREADS: u8 = 3;

/// Alias de type pour les clés de chiffrement RSA, qui sont des paires de clés numériques (n, e).
pub type PublicKey = KeyPair<NumKey, NumKey>;
/// Alias de type pour les clés de déchiffrement RSA, qui sont des paires de clés numériques (n, d).
pub type PrivateKey = KeyPair<NumKey, NumKey>;
/// Alias de type pour les clés principales RSA, qui sont des paires composés d'une clé de chiffrement et déchiffrement RSA (publique et privée).
/// Somme toute, une clé principale RSA est une paire de paire de clés numériques.
pub type RsaKey = KeyPair<PublicKey, PrivateKey>;

/// Implémentation d'un moteur cryptographique RSA complet.
pub struct Rsa;

impl Engine for Rsa
{
    type EncryptionKey = PublicKey;
    type DecryptionKey = PrivateKey;
    type MainKey = RsaKey;

    fn generate(&self, sz_b: u64, n_threads: u8) -> Self::MainKey 
    {
        let (g_tx, g_rx) = channel::unbounded();
        let (f_tx, f_rx) = channel::unbounded();

        let working = Arc::new(atomic::AtomicBool::new(true));
        
        for _ in 0..n_threads
        {
            let g_rx_c = g_rx.clone();
            
            let f_tx_c = f_tx.clone();
            let f_rx_c = f_rx.clone();
            
            let working_f_c = working.clone();
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

        while working.load(atomic::Ordering::Relaxed)
        {
            g_tx.send(maths::rand_primelike(sz_b)).expect("Rsa.generate : erreur dans la génération.");
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
            KeyPair::from(NumKey::from(n), NumKey::from(d.to_biguint().unwrap()))
        )
    }

    fn gen_def(&self) -> Self::MainKey 
    {
        self.generate(RSA_DEF_PRIME_SIZEB, RSA_DEF_GEN_THREADS)  
    }

    fn run_crypt(&self, num: &mut BigUint, key: &Self::EncryptionKey) {
        *num = maths::fmodpow(num, &key.1, &key.0);
    }

    fn run_decrypt(&self, num: &mut BigUint, key: &Self::DecryptionKey) {
        *num = maths::fmodpow(num, &key.1, &key.0)
    }
}