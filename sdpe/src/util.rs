use std::{fs::{read_to_string, write}, time};
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
                String::from("export : Extrait la partie d'une clé. Le type de clé détermine le type de destination ; la partie exportée sera écrite dans le fichier de sortie (--output)."),
                String::from("          Le fichier clé doit contenir une clé principale (paire clé publique / privée)."),
                String::from("          Les types possibles sont PUBLIC, PRIVATE, MAIN (copie de la clé principale).")
            ]
        }
    }

    pub fn op(&self, op: &str, args: &clap::ArgMatches)
    {
        match self
        {
            Self::Rsa(rsa) => {
                let kpath = args.value_of("keyfile").unwrap();
                match op
                {
                    "gen" => {
                        let ksize: u64 = 
                            if args.is_present("keysize")
                            {
                                args.value_of("keysize").unwrap().parse().expect("La taille de clé spécifiée n'est pas valide.")
                            }
                            else
                            {
                                PRIME_SIZEB
                            };
                        let nthreads: u8 =
                            if args.is_present("genthreads")
                            {
                                args.value_of("genthreads").unwrap().parse().expect("Le nombre de threads spécifiés n'est pas valide")
                            }
                            else
                            {
                                GEN_THREADS
                            };

                        if ksize > 128
                        {
                            println!("Attention : vous avez spécifié une taille de clé pour RSA supérieure à 128. L'opération peut prendre un certain temps.");
                            println!("  A titre indicatif, une génération en 256 octets prend entre 1m et 1m30s");
                        }
                        println!("Début de la génération d'une paire de clés RSA de taille {} octets, soit RSA-{} ({} threads)...", ksize, ksize * 16, nthreads);
                        let tpoint = time::Instant::now();
                        let k = rsa.generate(ksize, nthreads);

                        match args.value_of("keytype").unwrap().to_lowercase().as_str()
                        {
                            "main" | "pair" | "all" | "any" => (),
                            _ => {
                                println!("Vous avez spécifié une option autre que MAIN pour le type de clé à générer, mais cela est impossible pour RSA.");
                                println!("Si vous souhaitez obtenir uniquement une clé publique ou privée, vous devriez utiliser l'opération `export` (voir --help).");
                            }
                        }

                        write(kpath, k.serialize_str()).expect("Impossible d'écrire la clé dans le fichier clé.");
                        println!("Clé générée et écrite avec succès en {} secondes", tpoint.elapsed().as_secs());
                    },
                    "encrypt" | "decrypt" | "sign" | "verify" => {
                        let kt = args.value_of("keytype").unwrap().to_lowercase();
                        let rk = read_to_string(kpath).expect("Impossible de lire le fichier clé.");
                        let (puk, prk) = 
                            match kt.as_str()
                            {
                                "main" | "pair" => {
                                    let rk = RsaKey::from_str(String::from(rk)).expect("Impossible de charger la clé");
                                    (Some(rk.0), Some(rk.1))
                                },
                                "public" | "publ" => {
                                    (Some(PublicKey::from_str(String::from(rk)).expect("Impossible de charger la clé.")), None)
                                },
                                "private" | "priv" => {
                                    (None, Some(PrivateKey::from_str(String::from(rk)).expect("Impossible de charger la clé.")))
                                },
                                _ => {
                                    eprintln!("Type de clé invalide : {}", kt);
                                    return;
                                }
                            };

                        let msg = read_to_string(args.value_of("input").unwrap()).expect("Impossible de lire le fichier en entrée");
                        let outpath = args.value_of("output").unwrap();

                        match op
                        {
                            "encrypt" | "sign" => {
                                let mut msg = if args.is_present("raw") { Message::parts_str(msg, false).build() } else { Message::str(msg).build() };

                                match op
                                {
                                    "encrypt" => {
                                        rsa.encrypt(&mut msg, &puk.expect("Impossible d'encrypter sans clé publique."));
                                
                                        write(outpath, msg.to_parts_str()).expect("Impossible d'écrire dans le fichier de sortie");
                                        println!("Message chiffré et écrit avec succès.");
                                    },
                                    "sign" => {
                                        rsa.encrypt(&mut msg, &prk.expect("Impossible de signer sans clé privée."));

                                        write(outpath, msg.to_parts_str()).expect("Impossible d'écrire dans le fichier de sortie.");
                                        println!("Message signé et écrit avec succès.");
                                    },
                                    _ => ()
                                }
                            },
                            "decrypt" | "verify" => {
                                let mut msg = Message::parts_str(msg, true).build();

                                match op
                                {
                                    "decrypt" => {
                                        rsa.decrypt(&mut msg, &prk.expect("Impossible de décrypter sans clé privée"));

                                        let contents = if args.is_present("raw") { msg.to_parts_str() } else { msg.to_str().expect("Impossible de convertir le message.") };
                                        write(outpath, contents).expect("Impossible d'écrire dans le fichier de sortie");
                                        println!("Message déchiffré et écrit avec succès.");
                                    },
                                    "verify" => {
                                        rsa.decrypt(&mut msg, &puk.expect("Impossible de vérifier sans clé publique."));

                                        let contents = if args.is_present("raw") { msg.to_parts_str() } else { msg.to_str().expect("Impossible de convertir le message.") };
                                        write(outpath, contents).expect("Impossible d'écrire dans le fichier de sortie");
                                        println!("Message vérifié et écrit avec succès ; vérifiez sa cohérence.");
                                    },
                                    _ => ()
                                }
                            },
                            _ => {
                                eprintln!("Opération {} non reconnue pour ce moteur.", op);
                            }
                        }
                    },
                    "export" => {
                        let kt = args.value_of("keytype").unwrap().to_lowercase();
                        let rk = read_to_string(kpath).expect("Impossible de lire le fichier clé.");
                        let rk = RsaKey::from_str(String::from(rk)).expect("Impossible de charger la clé.");

                        if !args.is_present("output")
                        {
                            eprintln!("Aucun fichier de sortie indiqué pour l'export.");
                            return;
                        }

                        let (wstr, lbl) = 
                            match kt.as_str()
                            {
                                "public" | "publ" => (rk.0.serialize_str(), "publique"),
                                "private" | "priv" => (rk.1.serialize_str(), "privée"),
                                "main" | "pair" | "all" | "any" => (rk.serialize_str(), "principale"),
                                _ => {
                                    println!("Type de clé à exporter {} non reconnu. Liste : public, private, main (copie).", kt);
                                    return;
                                }
                            };
                        write(args.value_of("output").unwrap(), wstr).expect("Impossible d'écrire dans le fichier de destination.");
                        println!("Clé exportée sous sa forme {} avec succès.", lbl);
                    }
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