use std::fs::{read_to_string, write};
use rrsa::{engines::*, keys::*, messages::Message};


pub enum GenEngine
{
    Rsa(Rsa)
}

impl GenEngine
{
    pub fn list() -> Vec<String>
    {
        vec![
            String::from("rsa")
        ]
    }

    pub fn oplist(&self) -> Vec<String>
    {
        match self
        {
            Self::Rsa(_) => vec![
                String::from("publ : Extrait la partie publique d'une clé RSA et l'écrit dans un fichier destination")
            ]
        }
    }

    pub fn op(&self, op: &str, args: &clap::ArgMatches)
    {
        match self
        {
            Self::Rsa(rsa) => {
                match op
                {
                    "gen" => {
                        write(args.value_of("keyfile").unwrap(), rsa.gen_def().serialize_str()).expect("Impossible d'écrire la clé dans le fichier clé.");
                        println!("Clé générée et écrite avec succès.");
                    },
                    "encrypt" => {
                        let k = read_to_string(args.value_of("keyfile").unwrap()).expect("Impossible de lire le fichier clé.");
                        let k = RsaKey::from_str(String::from(k));

                        let msg = read_to_string(args.value_of("input").unwrap()).expect("Impossible de lire le fichier en entrée");
                        let mut msg = Message::str(msg).build();

                        rsa.encrypt(&mut msg, &k.0);

                        write(args.value_of("output").unwrap(), msg.to_parts_str()).expect("Impossible d'écrire dans le fichier de sortie");
                        println!("Message chiffré et écrit avec succès.");
                    },
                    "decrypt" => {
                        let k = read_to_string(args.value_of("keyfile").unwrap()).expect("Impossible de lire le fichier clé.");
                        let k = RsaKey::from_str(String::from(k));

                        let msg = read_to_string(args.value_of("input").unwrap()).expect("Impossible de lire le fichier en entrée");
                        let mut msg = Message::parts_str(msg, true).build();

                        rsa.decrypt(&mut msg, &k.1);

                        write(args.value_of("output").unwrap(), msg.to_str().expect("Impossible de convertir le message.")).expect("Impossible d'écrire dans le fichier de sortie");
                        println!("Message déchiffré et écrit avec succès.");
                    },
                    _ => ()
                }
            }
        }
    }

    pub fn resolve(engine: &str) -> Option<GenEngine> 
    {
        match engine 
        {
            "rsa" => Some(GenEngine::Rsa(Rsa {})),
            _ => None,
        }
    }
}