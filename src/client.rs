
pub struct Client {
}

impl Client {
    pub fn new() -> Client {
        Client {}
    }

    pub fn open(self, url: &str) {
        let _parsed = super::sqrl_url::SqrlUrl::parse(url);
    }
}
