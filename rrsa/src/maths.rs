use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{One, identities::Zero};
use rand::Rng;
use std::convert::TryInto;


pub trait NumUtil
{
    fn sz(&self, radix: u32) -> usize;
    fn sz_b(&self) -> usize
    {
        (self.sz(16) + 1) / 2
    }

    fn expl_f(&self, buf: &mut Vec<BigUint>, block_sz: usize);
    fn expl_r(&self, block_sz: usize) -> Vec<BigUint>
    {
        let mut buf: Vec<BigUint> = Vec::new();
        self.expl_f(&mut buf, block_sz);

        buf
    }
}

impl NumUtil for BigUint
{
    fn sz(&self, radix: u32) -> usize
    {
        self.to_str_radix(radix).len()
    }

    fn expl_f(&self, buf: &mut Vec<BigUint>, block_sz: usize)
    {
        let m = BigUint::from(2u8).pow((block_sz * 8).try_into().unwrap());
        let mut op = self.clone();

        while !op.is_zero()
        {
            buf.push(&op % &m);
            op /= &m;
        }

        buf.reverse();
    }
}


pub trait VecNumUtil
{
    fn rejoin(&self) -> BigUint;
}

impl VecNumUtil for Vec<BigUint>
{
    fn rejoin(&self) -> BigUint
    {
        if self.is_empty()
        {
            panic!("VecNumUtil.join (BigUint) : vecteur vide");
        }

        let mut b = BigUint::from(0u8);
        let mut mult;
        let base = BigUint::from(2u8);

        for part in self
        {
            mult = base.pow((part.sz_b() * 8).try_into().unwrap());
            b = &b * &mult + part;
        }

        b
    }
}

impl VecNumUtil for Vec<u8>
{
    fn rejoin(&self) -> BigUint
    {
        if self.is_empty()
        {
            panic!("VecNumUtil.join (u8) : vecteur vide");
        }

        let mut b = BigUint::from(0u8);
        let mult = BigUint::from(2u8).pow(8);

        for part in self
        {
            b = &b * &mult + part;
        }

        b
    }
}


const EXPCODE_TAB: [u8; 35] = [ 2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149 ];
const PRIME_RN: u32 = 12737213u32;
const PRIME_ROUNDS: u8 = 16;

pub fn fmodpow(base: &BigUint, exp: &BigUint, num: &BigUint) -> BigUint
{
    let mut res = BigUint::from(1u8);
    let mut exp_bin = exp.clone();
    let mut temp = base.clone();
    let mut r;

    while !exp_bin.is_zero()
    {
        r = &exp_bin % 2u8;
        if r.is_one()
        {
            res = (&res * &temp) % num;
        }

        exp_bin /= 2u8;
        temp = (&temp * &temp) % num;
    }

    res
}

pub fn euclide(a: &BigInt, b: &BigInt) -> BigInt
{
    let (mut r1, mut r2) = (a.clone(), b.clone());
    let (mut u1, mut u2) = (BigInt::from(1u8), BigInt::from(0u8));
    let (mut v1, mut v2) = (BigInt::from(1u8), BigInt::from(0u8));
    let (mut u3, mut v3, mut r3);
    let mut q;

    while !r2.is_zero()
    {
        q = &r1 / &r2;
        r3 = r1;
        u3 = u1;
        v3 = v1;
        r1 = r2;
        u1 = u2;
        v1 = v2;
        r2 = &r3 - &q * &r1;
        u2 = &u3 - &q * &u1;
        v2 = &v3 - &q * &v1;
    }

    u1
}

pub fn expcode(num: &BigUint) -> Option<BigUint>
{
    for &i in EXPCODE_TAB.iter()
    {
        if !(num % i).is_zero()
        {
            return Some(BigUint::from(i));
        }
    }

    None
}

pub fn isprime(num: &BigUint) -> bool
{
    for _ in 0..PRIME_ROUNDS
    {
        if !fmodpow(&(&PRIME_RN % num), &(num - 1u8), num).is_one()
        {
            return false;
        }
    }

    true
}

pub fn rand_primelike(szb: u64) -> BigUint
{
    let mut b = rand::thread_rng().gen_biguint(szb * 8);
    b /= 10u8;
    b *= 10u8;

    let mut digit = 0u8;
    while digit % 2 == 0 || digit == 5
    {
        digit = rand::thread_rng().gen_range(1..10);
    }
    b += digit;

    b
}