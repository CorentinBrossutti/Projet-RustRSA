use std::{error::Error, fmt::Display, ops::Deref};
use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num;


/// Délimiteur des différentes parties des clés pour la sérialisation textuelle.
const KEY_SERIAL_DELIMITER: &str = "::";
/// Base (radix) à utiliser pour sérialiser les parties numériques des clés.
const KEY_SERIAL_RADIX: u8 = 36;


/// Structure à utiliser lorsqu'une erreur a lieu au traitement d'une clé (chargement depuis un fichier, désérialisation...)
#[derive(Debug)]
pub struct KeyParseError
{
    msg: String,
    underlying: Option<ParseBigIntError>
}

impl KeyParseError
{
    fn from(msg: &str, underlying: Option<ParseBigIntError>) -> Self
    {
        KeyParseError
        {
            msg: String::from(msg),
            underlying
        }
    }
}

impl Display for KeyParseError
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        let mut disp = String::from("Impossible de désérialiser une clé (KeyParseError) : ");
        disp.push_str(&self.msg);

        if let Some(ul) = &self.underlying
        {
            if let Err(e) = disp.fmt(f)
            {
                return Err(e);
            }
            return ul.fmt(f);
        }

        disp.fmt(f)
    }
}

impl Error for KeyParseError {}

/// Trait à implémenter par toutes les clés, impose de définir certaines méthodes liées à la sérialisation.
pub trait Key
{
    /// Permet d'obtenir une clé depuis sa sérialisation textuelle.
    fn from_str(val: String) -> Result<Self, KeyParseError> where Self : Sized;
    /// Retourne la sérialisation textuelle de la clé.
    fn serialize_str(&self) -> String; 
}


/// Clé numérique, contient juste un grand entier positif.
pub struct NumKey
{
    /// Valeur numérique de la clé (grand entier).
    pub value: BigUint
}

impl NumKey
{
    /// Construit une clé numérique depuis un grand entier.
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
    fn from_str(val: String) -> Result<Self, KeyParseError>
    {
        let value = BigUint::from_str_radix(&val, KEY_SERIAL_RADIX.into());
        match value
        {
            Ok(x) => Ok(NumKey { value: x }),
            Err(e) => Err(KeyParseError::from("", Some(e)))
        }
    }

    fn serialize_str(&self) -> String
    {
        self.value.to_str_radix(KEY_SERIAL_RADIX.into()) 
    }
}

/// L'implémentation de `Deref` permet de traiter la clé numérique comme un grand entier
impl Deref for NumKey
{
    type Target = BigUint;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}


/// Une paire de clé dont les types sont génériques. La structure elle-même est considérée comme une clé.
pub struct KeyPair<T : Key, U : Key>(pub T, pub U);

impl<T : Key, U : Key> KeyPair<T, U>
{
    /// Construit une paire de clés depuis deux autres clés (types génériques de l'implémentation).
    pub fn from(key1: T, key2: U) -> KeyPair<T, U>
    {
        KeyPair(key1, key2)
    }
}

impl<T : Key, U : Key> Key for KeyPair<T, U>
{
    fn from_str(val: String) -> Result<Self, KeyParseError>
    {
        // On découpe chaque partie en utilisant le séparateur.
        let parts: Vec<&str> = val.split(KEY_SERIAL_DELIMITER).collect();
        let len = parts.len();

        // Puisqu'on traite une paire de clés, la longueur est forcément paire.
        if len % 2 == 1
        {
            return Err(KeyParseError::from("KeyPair::from_str : impossible de traiter un nombre de parties impair.", None));
        }

        // On obtient la première clé depuis la première moitié du texte...
        let ts = T::from_str(parts[..(len / 2)].join(KEY_SERIAL_DELIMITER))?;
        // Puis la deuxième moitié.
        let us = U::from_str(parts[(len / 2)..len].join(KEY_SERIAL_DELIMITER))?;
        // On retourne un résultat ok.
        Ok(KeyPair(ts, us))
    }

    fn serialize_str(&self) -> String
    {
        format!("{}{}{}", self.0.serialize_str(), KEY_SERIAL_DELIMITER, self.1.serialize_str())
    }
}