use std::string::FromUtf8Error;
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use crate::{maths::{NumUtil, VecNumUtil}, engines};

const NUM_STRING_RADIX: u8 = 36;
const PARTS_STR_SEP: &str = ":";

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
        let nval = if let Some(nval) = self.nval { nval } else { self.strv.unwrap().into_bytes().rejoin() };
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
    pub fn str(strv: String) -> MessageBuilder
    {
        MessageBuilder
        {
            nval: None,
            parts: None,
            strv: Some(strv),
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

    pub fn nstr(nstr: String, encrypted: bool) -> MessageBuilder
    {
        Message::num(BigUint::from_str_radix(nstr.as_str(), NUM_STRING_RADIX.into()).unwrap(), encrypted)
    }

    pub fn parts(parts: Vec<BigUint>, encrypted: bool) -> MessageBuilder
    {
        if parts.is_empty()
        {
            panic!("Message::parts : impossible de construire un message depuis un ensemble vide.");
        }

        MessageBuilder
        {
            nval: Some(parts.rejoin()),
            parts: Some(parts),
            strv: None,
            bsize: None,
            padsize: None,
            encrypted: Some(encrypted)
        }
    }

    pub fn parts_str(pstr: String, encrypted: bool) -> MessageBuilder
    {
        Message::parts(pstr.split(PARTS_STR_SEP).map(| ps | {
            BigUint::from_str_radix(ps, NUM_STRING_RADIX.into()).unwrap()
        }).collect(), encrypted)
    }

    pub fn part(&self, index: usize) -> &BigUint
    {
        &self.parts[index]
    }

    pub fn refresh_nval(&mut self)
    {
        self.nval = self.parts.rejoin();
    }

    pub fn refresh_parts(&mut self)
    {
        self.parts.clear();
        self.nval.expl_f(&mut self.parts, self.bsize);
    }

    pub fn to_str(&self) -> Result<String, FromUtf8Error>
    {
        let v = self.nval.expl_r(1);
        let bytes = v.iter().map(| num | {
            num.to_u8().unwrap_or(0x3f)
        }).collect();

        String::from_utf8(bytes)
    }

    pub fn to_nstr(&self) -> String
    {
        self.nval.to_str_radix(NUM_STRING_RADIX.into())
    }

    pub fn to_parts_str(&self) -> String
    {
        let parts_str: Vec<String> = self.parts.iter().map(| part | {
            part.to_str_radix(NUM_STRING_RADIX.into())
        }).collect();
        parts_str.join(PARTS_STR_SEP)
    }
}