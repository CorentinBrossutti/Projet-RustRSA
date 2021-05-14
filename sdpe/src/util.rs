use rrsa::engines;


pub enum GenEngine
{
    Rsa(engines::Rsa)
}

impl GenEngine
{
    pub fn oplist(&self) -> Vec<String>
    {
        match self
        {
            Self::Rsa(rsa) => vec![
                String::from("publ : Extrait la partie publique d'une clé RSA et l'écrit dans un fichier destination")
            ]
        }
    }

    pub fn op(&self, args: clap::ArgMatches)
    {
        match self
        {
            Self::Rsa(rsa) =>
            {
                
            }
        }
    }
}