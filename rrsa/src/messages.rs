use std::string::FromUtf8Error;
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use crate::{maths::{NumUtil, VecNumUtil}, engines};

/// Base (radix) à utiliser pour la transformation d'un message en sa version textuelle numérique (`to_nstr`).
const NUM_STRING_RADIX: u32 = 36;
/// Séparateur à utiliser lorsque le message est transformé en la représentation textuelle de ses parties (`to_parts_str`)
const PARTS_STR_SEP: &str = ":";

/// Structure du builder pattern permettant de construire un message avec des arguments optionnels
pub struct MessageBuilder
{
    nval: Option<BigUint>,
    parts: Option<Vec<BigUint>>,
    strv: Option<String>,
    bsize: Option<u32>,
    padsize: Option<u32>,
    encrypted: Option<bool>
}

impl MessageBuilder
{
    /// Définit la taille de bloc du message en octets.
    pub fn bsize(mut self, bsize: u32) -> Self
    {
        self.bsize = Some(bsize);
        self
    }

    /// Définit la taille en octets du nonce à appliquer à chaque partie.
    pub fn padsize(mut self, padsize: u32) -> Self
    {
        self.padsize = Some(padsize);
        self
    }

    /// Construit le message avec les options indiquées.
    pub fn build(self) -> Message
    {
        let bsize = if let Some(bsize) = self.bsize { bsize } else { engines::BSIZE_DEF };
        // La valeur numérique est soit celle indiquée dans le builder, soit la recomposition de la valeur textuelle (seul cas où la valeur numérique n'est pas calculée)
        let nval = if let Some(nval) = self.nval { nval } else { self.strv.unwrap().into_bytes().rejoin() };
        // Les parties sont donc soit déjà présentes, soit elles sont calculées
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


/// Un message, soit une classe "wrapper" facilitant le chiffrement / déchiffrement, notamment en gérant la conversion en valeur numérique, le découpage, etc.
/// Peut être construit de nombreuses manières, et utilise pour ce faire le pattern builder avec la structure `MessageBuilder`.
pub struct Message
{
    pub nval: BigUint,
    pub parts: Vec<BigUint>,
    pub bsize: u32,
    pub padsize: u32,
    pub encrypted: bool
}

impl Message
{
    /// Initialise la construction d'un message depuis un texte quelconque.
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

    /// Initialise la construction d'un message depuis un nombre (grand entier).
    /// Le booléen `encrypted` permet d'indiquer si le nombre est déjà, ou non, chiffré.
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

    /// Initialise la construction d'un message depuis la représentation textuelle de sa valeur numérique.
    /// Le booléen `encrypted` permet d'indiquer si le nombre est déjà, ou non, chiffré.
    pub fn nstr(nstr: String, encrypted: bool) -> MessageBuilder
    {
        Message::num(BigUint::from_str_radix(nstr.as_str(), NUM_STRING_RADIX).unwrap(), encrypted)
    }

    /// Initialise la construction d'un message depuis ses parties.
    /// Le booléen `encrypted` indique si oui ou non les parties sont déjà chiffrées.
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

    /// Initialise la construction d'un message depuis la représentation textuelle de ses parties.
    /// Le booléen `encrypted` indique si oui ou non les parties sont déjà chiffrées.
    pub fn parts_str(pstr: String, encrypted: bool) -> MessageBuilder
    {
        Message::parts(pstr.split(PARTS_STR_SEP).map(| ps | {
            BigUint::from_str_radix(ps, NUM_STRING_RADIX).unwrap()
        }).collect(), encrypted)
    }

    /// Retourne une référence sur la partie à l'indice donné.
    pub fn part(&self, index: usize) -> &BigUint
    {
        &self.parts[index]
    }

    /// Rafraîchit la valeur numérique du message depuis les parties (si ces dernières ont été modifiées).
    pub fn refresh_nval(&mut self)
    {
        self.nval = self.parts.rejoin();
    }

    /// Rafraîchit les parties du message depuis sa valeur numérique (si cette dernière a été modifiée).
    pub fn refresh_parts(&mut self)
    {
        self.parts.clear();
        self.nval.expl_f(&mut self.parts, self.bsize);
    }

    /// Tente de convertir le message en une chaîne UTF-8.
    /// Peut échouer si le message est chiffré, invalide, etc.
    pub fn to_str(&self) -> Result<String, FromUtf8Error>
    {
        // On décompose la valeur numérique actuelle en blocs de taille 1 seul octet
        // Afin de pouvoir ensuite...
        let v = self.nval.expl_r(1);
        // ...décomposer chaque octet en u8
        // 0x3f correspond au point d'interrogation en cas de problème sur un caractère en particulier
        let bytes = v.iter().map(| num | {
            num.to_u8().unwrap_or(0x3f)
        }).collect();

        // Conversion des octets en chaîne
        String::from_utf8(bytes)
    }

    /// Convertit le message en la représentation textuelle de sa valeur numérique.
    pub fn to_nstr(&self) -> String
    {
        self.nval.to_str_radix(NUM_STRING_RADIX)
    }

    /// Convertit le message en la représentation textuelle de ses parties.
    pub fn to_parts_str(&self) -> String
    {
        // Chaque partie est convertie en texte (grand entier -> texte)
        let parts_str: Vec<String> = self.parts.iter().map(| part | {
            part.to_str_radix(NUM_STRING_RADIX)
        }).collect();
        // Puis chaque partie est rejointe en une seule chaîne dont les parties sont séparées par `PARTS_STR_SEP`
        parts_str.join(PARTS_STR_SEP)
    }
}