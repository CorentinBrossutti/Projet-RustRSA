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
                .help("Moteur de cryptage à utiliser (--list pour la liste)")
                .takes_value(true)
                .required_unless("list")
        )
        .arg(
            clap::Arg::with_name("operation")
                .short("p")
                .long("op")
                .value_name("LIBELLE")
                .help("Opération à effectuer (--list pour la liste)")
                .takes_value(true)
                .required_unless("list")
        )
        .arg(
            clap::Arg::with_name("keyfile")
                .short("k")
                .long("kf")
                .value_name("FICHIER_CLE")
                .help("Chemin du fichier contenant la clé")
                .takes_value(true)
                .required_unless("list")
        )
        .arg(
            clap::Arg::with_name("keytype")
                .short("t")
                .long("kt")
                .value_name("TYPE_CLE")
                .help("Type de clé à traiter / générer : PUBLIC, PRIVATE, MAIN")
                .takes_value(true)
                .required_unless("list")
        )
        .arg(
            clap::Arg::with_name("keysize")
                .short("s")
                .long("ks")
                .value_name("TAILLE_CLE_OCTETS")
                .help("Taille en octets de la clé pour la génération. Pour le RSA, il faut multiplier par 16 (RSA2048 = 128). Si omis, une valeur par défaut sera utilisée")
                .takes_value(true)
        )
        .arg(
            clap::Arg::with_name("genthreads")
                .short("g")
                .long("gt")
                .value_name("NOMBRE_THREADS")
                .help("Nombre de threads à utiliser pour la génération de clés. Particulièrement utile pour RSA par exemple. Si omis, un nombre par défaut sera utilisé")
                .takes_value(true)
        )
        .arg(
            clap::Arg::with_name("input")
                .short("i")
                .long("in")
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
                .long("out")
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
                .short("l")
                .long("list")
                .help("Liste les moteurs et les opérations disponibles")
        )
        .arg(
            clap::Arg::with_name("raw")
                .short("r")
                .long("raw")
                .help(
                    "Si présent, indique que le traitement doit se faire de manière brute : \
                    pour le chiffrement, les données en entrées sont considérées brutes ; \
                    pour le déchiffrement, les données sont écrites en sortie de manière brute. \
                    Cette option est utile pour les chiffrements et déchiffrement successifs ; \
                    auquel cas il faut toujours l'indiquer, sauf pour le premier chiffrement et le dernier déchiffrement"
                )
        )
        .get_matches();

    if matches.is_present("list") 
    {
        println!();
        println!("Moteurs cryptographiques disponibles :");
        for engine in GenEngine::list()
        {
            println!("- {}", engine);
        }
        println!();
        println!("Opérations disponibles pour tous les moteurs :");
        println!("- gen : Génère une clé principale dans le fichier de clé spécifié avec [keyfile]");
        println!("- encrypt : Chiffre le message écrit dans [input] avec [keyfile] puis l'écrit dans [output]");
        println!("- decrypt : Déchiffre le message chiffré écrit dans [input] avec [keyfile] puis l'écrit dans [output]");
        println!("- sign : Signe le message écrit dans [input] avec [keyfile] puis écrit le message signé dans [output]");
        println!("- verify : Déchiffre un message signé dans [input] avec [keyfile] puis écrit le résultat pour vérification dans [output]");
        for engine in GenEngine::list()
        {
            println!();
            println!("Opérations spécifiques au moteur {} :", engine);
            if let Some(engine) = GenEngine::resolve(&engine) 
            {
                for op in engine.oplist()
                {
                    println!("- {}", op.1);
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
