use std::ops::Deref;
use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num;


const KEY_SERIAL_DELIMITER: &str = "::";
const KEY_SERIAL_RADIX: u8 = 36;

pub trait Key
{
    fn from_str(val: String) -> Result<Self, ParseBigIntError> where Self : Sized;
    fn serialize_str(&self) -> String; 
}


pub struct NumKey
{
    pub value: BigUint
}

impl NumKey
{
    pub fn from(value: BigUint) -> NumKey
    {
        NumKey
        {
            value
        }
    }
}

impl Key for NumKey
{
    fn from_str(val: String) -> Result<Self, ParseBigIntError>
    {
        let value = BigUint::from_str_radix(&val, KEY_SERIAL_RADIX.into())?;
        Ok(NumKey
        {
            value
        })
    }

    fn serialize_str(&self) -> String 
    {
        self.value.to_str_radix(KEY_SERIAL_RADIX.into()) 
    }
}

impl Deref for NumKey
{
    type Target = BigUint;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}


pub struct KeyPair<T : Key, U : Key>(pub T, pub U);

impl<T : Key, U : Key> KeyPair<T, U>
{
    pub fn from(key1: T, key2: U) -> KeyPair<T, U>
    {
        KeyPair(key1, key2)
    }
}

impl<T : Key, U : Key> Key for KeyPair<T, U>
{
    fn from_str(val: String) -> Result<Self, ParseBigIntError>
    {
        let parts: Vec<&str> = val.split(KEY_SERIAL_DELIMITER).collect();
        let len = parts.len();

        if len % 2 == 1
        {
            panic!("KeyPair.from_str : impossible de construire une clé depuis un nombre de parties impair.");
        }

        let ts = T::from_str(parts[..(len / 2)].join(KEY_SERIAL_DELIMITER))?;
        let us = U::from_str(parts[(len / 2)..len].join(KEY_SERIAL_DELIMITER))?;
        Ok(KeyPair(ts, us))
    }

    fn serialize_str(&self) -> String
    {
        format!("{}{}{}", self.0.serialize_str(), KEY_SERIAL_DELIMITER, self.1.serialize_str())
    }
}