use sodiumoxide::crypto::sign;
use crate::util;
use crate::sqrl_url::SqrlUrl;
use std::convert::TryInto;

pub struct Client {
    client: reqwest::blocking::Client,
    parsed: SqrlUrl,
    last_server: String,
}

impl Client {
    pub fn new(url: &str) -> Client {
        sodiumoxide::init().unwrap();
        let parsed = SqrlUrl::parse(url);
        Client {
            client: reqwest::blocking::Client::new(),
            parsed: parsed,
            last_server: url.to_string(),
        }
    }

    pub fn open(&mut self, imk: Vec<u8>) {
        let (public, secret) = self.create_keys(&self.parsed.auth_domain(), imk);
        let query = ClientQuery::new(&self.last_server, ClientCommand::Query, public);
        self.post_server(&self.parsed.url_resource.clone(), &query.value(secret));
    }

    fn post_server(&mut self, path: &str, data: &Vec<(&str, String)>) {
        let url = format!("https://{}{}", self.parsed.domain, path);
        let response = self.client.post(url).form(&data).send().unwrap().text().unwrap();
        self.last_server = util::decode64(response);
        println!("{:?}", self.last_server);
    }

    fn create_keys(&self, auth_domain: &str, imk: Vec<u8>) -> (sign::PublicKey, sign::SecretKey) {
        use sodiumoxide::crypto::auth;
        let tag = auth::authenticate(auth_domain.as_bytes(), &auth::Key(imk.try_into().unwrap()));
        sign::ed25519::keypair_from_seed(&sign::Seed(tag.0))
    }
}

pub struct Sqrl64 {
    pub base64: String,
}

impl Sqrl64 {
    pub fn from_base64(base64: &str) -> Sqrl64 {
        Sqrl64 {
            base64: base64.to_string(),
        }
    }

    pub fn from_string(string: &str) -> Sqrl64 {
        Sqrl64 {
            base64: util::encode64(string),
        }
    }

    pub fn from_bin(bin: &[u8]) -> Sqrl64 {
        Sqrl64 {
            base64: util::encode64(bin),
        }
    }

    #[allow(dead_code)]
    fn decode(&self) -> String {
        util::decode64(&self.base64)
    }
}


struct ClientQuery {
    client: ClientParameters,
    server: Sqrl64,
    // ids: String,
}

impl ClientQuery {
    pub fn new(server: &str, command: ClientCommand, public: sign::PublicKey) -> ClientQuery {
        let client_params = ClientParameters::new(command, public);
        ClientQuery {
            server: Sqrl64::from_string(server),
            client: client_params,
            // ids: "".to_string(),
        }
    }

    fn data_to_sign(&self) -> String {
        format!("{}{}",
                self.client.value().base64,
                self.server.base64, 
               )
    }

    fn signed_data(&self, key: sign::SecretKey) -> String {
        Sqrl64::from_bin(&sign::ed25519::sign(self.data_to_sign().as_bytes(), &key)).base64
    }
    
    pub fn value(&self, key: sign::SecretKey) -> Vec<(&str, String)> {
        [
            ("client", self.client.value().base64.clone()),
            ("server", self.server.base64.clone()),
            ("ids", self.signed_data(key)),
        ].to_vec()

    }
}

struct ClientParameters {
    versions: String,
    command: ClientCommand,
    // IDentity Key
    // Elliptic curve public key derived from the user's
    // Identiy Master Key (IMK) by the HMAC hash of the site's
    // effective domain name. The binary key is base64url encoded
    // with trailing equals sign padding removed
    idk: sign::PublicKey,
    // optional params
    // opt,btn,pidk,ins,pins,suk,vuk
    // params: Vec<(String, String)>,
}

impl ClientParameters {
    pub fn new(command: ClientCommand, idk: sign::PublicKey) -> ClientParameters {
        ClientParameters {
            versions: "1".to_string(),
            command: command,
            idk: idk,
            // params: Vec::new(),
        }
    }

    fn pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        pairs.push(("ver".to_string(), self.versions.clone()));
        pairs.push(("cmd".to_string(), self.command.to_string()));
        pairs.push(("idk".to_string(), Sqrl64::from_bin(&self.idk.0).base64));
        //pairs.push(("opt".to_string(), Sqrl64::from_string("cps").base64));

        pairs
    }

    pub fn value(&self) -> Sqrl64 {
        Sqrl64::from_string(
            // TODO: escape
            &self.pairs().into_iter().map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>().join("\r\n")
        )
    }
}

#[allow(dead_code)]
enum ClientCommand {
    Query,
    Ident,
    Disable,
    Enable,
    Remove,
}

impl ClientCommand {
    pub fn to_string(&self) -> String {
        match self {
            ClientCommand::Query => "Query",
            ClientCommand::Ident => "Ident",
            ClientCommand::Disable => "Disable",
            ClientCommand::Enable => "Enable",
            ClientCommand::Remove => "Remove",
        }.to_string()
    }
}
