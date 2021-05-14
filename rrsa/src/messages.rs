use num_bigint::BigUint;
use num_traits::ToPrimitive;
use crate::{maths::{NumUtil, VecNumUtil}, engines};


pub struct MessageBuilder
{
    nval: Option<BigUint>,
    parts: Option<Vec<BigUint>>,
    strv: Option<String>,
    bsize: Option<usize>,
    padsize: Option<usize>,
    encrypted: Option<bool>
}

impl MessageBuilder
{
    pub fn bsize(mut self, bsize: usize) -> Self
    {
        self.bsize = Some(bsize);
        self
    }

    pub fn padsize(mut self, padsize: usize) -> Self
    {
        self.padsize = Some(padsize);
        self
    }

    pub fn build(self) -> Message
    {
        let bsize = if let Some(bsize) = self.bsize { bsize } else { engines::BSIZE_DEF };
        let nval = if let Some(nval) = self.nval
            {
                nval
            }
            else
            {
                let mut bytes = self.strv.unwrap().into_bytes();
                bytes.insert(0, 0u8);

                bytes.join()
            };
        let parts = if let Some(parts) = self.parts { parts } else { nval.expl_r(bsize) };

        Message
        {
            nval,
            parts,
            bsize,
            padsize: if let Some(padsize) = self.padsize { padsize } else { engines::PADSIZE_DEF },
            encrypted: self.encrypted.unwrap()
        }
    }
}

pub struct Message
{
    pub nval: BigUint,
    pub parts: Vec<BigUint>,
    pub bsize: usize,
    pub padsize: usize,
    pub encrypted: bool
}

impl Message
{
    pub fn str(strv: &str) -> MessageBuilder
    {
        MessageBuilder
        {
            nval: None,
            parts: None,
            strv: Some(String::from(strv)),
            bsize: None,
            padsize: None,
            encrypted: Some(false)
        }
    }

    pub fn num(num: BigUint, encrypted: bool) -> MessageBuilder
    {
        MessageBuilder
        {
            nval: Some(num),
            parts: None,
            strv: None,
            bsize: None,
            padsize: None,
            encrypted: Some(encrypted)
        }
    }

    pub fn parts(parts: Vec<BigUint>, encrypted: bool) -> MessageBuilder
    {
        if parts.len() == 0
        {
            panic!("Message::parts : impossible de construire un message depuis un ensemble vide.");
        }

        MessageBuilder
        {
            nval: Some(parts.join()),
            parts: Some(parts),
            strv: None,
            bsize: None,
            padsize: None,
            encrypted: Some(encrypted)
        }
    }

    pub fn part(&self, index: usize) -> &BigUint
    {
        &self.parts[index]
    }

    pub fn refresh_nval(&mut self)
    {
        self.nval = self.parts.join();
    }

    pub fn refresh_parts(&mut self)
    {
        self.nval.expl_f(&mut self.parts, self.bsize);
    }

    pub fn to_str(&self) -> String
    {
        let v = self.nval.expl_r(1);
        let mut it = v.iter();
        it.next();
        let bytes = it.map(| num | {
            num.to_u8().unwrap_or(0x3f)
        }).collect();

        String::from_utf8(bytes).unwrap()
    }
}