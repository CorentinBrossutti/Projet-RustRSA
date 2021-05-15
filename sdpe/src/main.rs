mod util;

use util::*;


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
        for engine in GenEngine::list()
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
        for engine in GenEngine::list()
        {
            println!();
            println!("Opérations spécifiques au moteur {}", engine);
            if let Some(engine) = GenEngine::resolve(&engine) 
            {
                for op in engine.oplist() 
                {
                    println!("- {}", op);
                }
            }
        }

        return;
    }

    if let Some(engine) = GenEngine::resolve(matches.value_of("engine").unwrap())
    {
        engine.op(matches.value_of("operation").unwrap(), &matches);
    }
    else
    {
        println!("Moteur invalide ou non spécifié. Utilisez <sdpe> list pour la liste.");
    }
}
