use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, identities::Zero};
use std::convert::TryInto;

const EXPCODE_TAB: [u8; 35] = [ 2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149 ];
const PRIME_RN: u32 = 12737213u32;
const PRIME_ROUNDS: u8 = 16;


pub trait NumUtil
{
    fn sz(&self, base: u32) -> usize;
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
    fn sz(&self, base: u32) -> usize
    {
        self.to_str_radix(base).len()
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

        buf.push(BigUint::from(0u8));
        buf.reverse();
    }
}


pub trait VecNumUtil
{
    fn join(&self) -> BigUint;
}

impl VecNumUtil for Vec<BigUint>
{
    fn join(&self) -> BigUint
    {
        if self.len() == 0
        {
            panic!("VecNumUtil.join (BigUint) : vecteur vide");
        }
        else if self.first().unwrap().is_one()
        {
            panic!("VecUtil.join (BigUint) : nombre marqué négatif pour BigUint");
        }

        let mut b = BigUint::from(0u8);
        let mut mult;
        let base = BigUint::from(2u8);

        let mut iter = self.iter();
        iter.next();
        for part in iter
        {
            mult = base.pow((part.sz_b() * 8).try_into().unwrap());
            b = &b * &mult + part;
        }

        b
    }
}

impl VecNumUtil for Vec<u8>
{
    fn join(&self) -> BigUint
    {
        if self.len() == 0
        {
            panic!("VecNumUtil.join (u8) : vecteur vide");
        }
        else if self.first().unwrap().is_one()
        {
            panic!("VecNumUtil.join (u8) : nombre marqué négatif pour u8");
        }

        let mut b = BigUint::from(0u8);
        let mult = BigUint::from(2u8).pow(8);

        let mut iter = self.iter();
        iter.next();
        for part in iter
        {
            b = &b * &mult + part;
        }

        b
    }
}


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

pub fn euclide(a: &BigUint, b: &BigUint) -> BigUint
{
    let (mut r1, mut r2) = (a.clone().to_bigint().unwrap(), b.clone().to_bigint().unwrap());
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

    u1.to_biguint().unwrap()
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