use sodiumoxide::crypto::sign;

pub struct Client {
}

impl Client {
    pub fn new() -> Client {
        Client {}
    }

    pub fn open(&self, url: &str, imk: Vec<u8>) {
        let parsed = super::sqrl_url::SqrlUrl::parse(url);
        //println!("{}", parsed.auth_domain());
        let (public, secret) = self.create_keys(&parsed.auth_domain(), imk);
        let client_params = crate::ClientParameters::new(
            crate::ClientCommand::Ident,
            public);
        let params = crate::QueryParameters::new(url, client_params);
        let query = crate::SignedQuery::generate_url(&format!("https://{}", &parsed.auth_domain()), params);
    }

    fn create_keys(&self, domain: &str, imk: Vec<u8>) -> (sign::PublicKey, sign::SecretKey) {
        sodiumoxide::init();
        use sodiumoxide::crypto::auth;
        use std::convert::TryInto;
        let tag = auth::authenticate(domain.as_bytes(), &auth::Key(imk.try_into().unwrap()));
        println!("{:02x?}", tag);
        sign::ed25519::keypair_from_seed(&sign::Seed(tag.0))
    }
}
