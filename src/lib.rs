// https://www.grc.com/sqrl/sqrl.htm
// https://www.grc.com/sqrl/userview.htm
// https://sqrlauth.net/Main_Page
// https://sqrlid.com/libsqrl/index.html
pub mod storage;
pub mod client;
pub mod sqrl_url;

// UserPerSitePrivateKey
//   make_public_key
//   sign

use sodiumoxide::crypto::sign;
use url::{Url, ParseError};
pub struct Sqrl64 {
    pub string: String,
    pub base64: String,
}
impl Sqrl64 {
    pub fn from_base64(base64: &str) -> Sqrl64 {
        Sqrl64 {
            string: Sqrl64::decode(base64),
            base64: base64.to_string(),
        }
    }
    pub fn from_string(string: &str) -> Sqrl64 {
        Sqrl64 {
            string: string.to_string(),
            base64: Sqrl64::encode(string),
        }
    }

    fn decode(base64: &str) -> String {
        // TODO
        "".to_string()
    }
    fn encode(string: &str) -> String {
        "".to_string()
    }
}

pub struct SignedQuery {
    parameters: QueryParameters,
}
impl SignedQuery {
    // pub fn new() -> SignedQuery {
    //     SignedQuery {}
    // }
    //
    pub fn generate_url(base: &str, params: QueryParameters) -> Url {
        let mut url = Url::parse(base).unwrap();
        {
            let mut pairs = url.query_pairs_mut();
            pairs.clear();
            for (k, v) in params.value() {
                pairs.append_pair(k, &v);
            }
        }
        url
    }

}

pub struct QueryParameters {
    client: ClientParameters,
    server: Sqrl64,
    ids: String,
}

impl QueryParameters {
    pub fn new(server: &str, client: ClientParameters) -> QueryParameters {
        QueryParameters {
            server: Sqrl64::from_string(server),
            client: client,
            ids: "".to_string(),
        }
    }

    fn data_to_sign(&self) -> String {
        format!("{}{}",
                self.client.value().base64,
                self.server.base64, 
               )
    }

    fn signed_data(&self, key: &str) -> String {
        "".to_string()
    }
    
    pub fn value(&self) -> Vec<(&str, String)> {
        let key = "primary key";
        [
            ("client", self.client.value().base64.clone()),
            ("server", self.server.base64.clone()),
            ("ids", self.signed_data(key)),
        ].to_vec()

    }
}

pub struct ClientParameters {
    versions: Vec<u8>,
    command: ClientCommand,
    // IDentity Key
    // Elliptic curve public key derived from the user's
    // Identiy Master Key (IMK) by the HMAC hash of the site's
    // effective domain name. The binary key is base64url encoded
    // with trailing equals sign padding removed
    idk: sign::PublicKey,
    // optional params
    // opt,btn,pidk,ins,pins,suk,vuk
    params: Vec<(String, String)>,
}

impl ClientParameters {
    pub fn new(command: ClientCommand, idk: sign::PublicKey) -> ClientParameters {
        ClientParameters {
            versions: [1].to_vec(),
            command: command,
            idk: idk,
            params: Vec::new(),
        }
    }
    pub fn value(&self) -> Sqrl64 {
        Sqrl64::from_string("")
    }
}

pub enum ClientCommand {
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
