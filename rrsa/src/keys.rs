pub trait Key
{
    fn serialize_str(&self) -> String; 
}


struct KeyPair<T : Key, U : Key>(T, U);