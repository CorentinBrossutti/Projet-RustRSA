mod util;

use util::*;
use rrsa::engines::Rsa;


fn resolve(engine: &str) -> Option<GenEngine> 
{
    match engine 
    {
        "rsa" => Some(GenEngine::Rsa(Rsa {})),
        _ => None,
    }
}

fn engines() -> Vec<String> 
{
    vec![String::from("rsa")]
}

fn main() 
{
    let matches = clap::App::new("Simple Data Privacy Engine")
        .version("0.1.0")
        .author("Corentin BROSSUTTI <corentin.brossutti@posteo.net>")
        .arg(
            clap::Arg::with_name("engine")
                .short("e")
                .long("engine")
                .value_name("MOTEUR")
                .help("Moteur de cryptage à utiliser (list pour la liste)")
                .takes_value(true)
                .required_unless("list")
        )
        .arg(
            clap::Arg::with_name("operation")
                .short("p")
                .long("operation")
                .value_name("LIBELLE")
                .help("Opération à effectuer (list pour la liste)")
                .takes_value(true)
                .required_unless("list")
        )
        .arg(
            clap::Arg::with_name("keyfile")
                .short("k")
                .long("keyfile")
                .value_name("FICHIER_CLE")
                .help("Chemin du fichier contenant la clé")
                .takes_value(true)
                .required_unless("list")
        )
        .arg(
            clap::Arg::with_name("input")
                .short("i")
                .long("input")
                .value_name("FICHIER_ENTREE")
                .help("Chemin du fichier en entrée contenant les données à traiter")
                .takes_value(true)
                .required_ifs(&[
                    ("operation", "encrypt"),
                    ("operation", "decrypt"),
                    ("operation", "sign"),
                    ("operation", "verify"),
                ])
        )
        .arg(
            clap::Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FICHIER_SORTIE")
                .help("Chemin du fichier en sortie recevant les données traitées")
                .required_ifs(&[
                    ("operation", "encrypt"),
                    ("operation", "decrypt"),
                    ("operation", "sign"),
                    ("operation", "verify"),
                ])
        )
        .arg(
            clap::Arg::with_name("list")
                .help("Liste les moteurs et les opérations")
        )
        .get_matches();

    if matches.is_present("list") 
    {
        println!("Moteurs cryptographiques disponibles :");
        for engine in engines() 
        {
            println!("- {}", engine);
        }
        println!();
        println!("Opérations disponibles pour tous les moteurs");
        println!("- gen : Génère une clé dans le fichier de clé spécifié avec [keyfile]");
        println!("- encrypt : Chiffre le message écrit dans [input] avec [keyfile] puis l'écrit dans [output]");
        println!("- decrypt : Déchiffre le message chiffré écrit dans [input] avec [keyfile] puis l'écrit dans [output]");
        println!("- sign : Signe le message écrit dans [input] avec [keyfile] puis écrit le message chiffré et signé dans [output]");
        println!("- verify : Déchiffre un message signé dans [input] avec [keyfile] puis écrit le résultat pour vérification dans [output]");
        for engine in engines() 
        {
            println!();
            println!("Opérations spécifiques au moteur {}", engine);
            if let Some(engine) = resolve(&engine) 
            {
                for op in engine.oplist() 
                {
                    println!("- {}", op);
                }
            }
        }

        return;
    }
}
