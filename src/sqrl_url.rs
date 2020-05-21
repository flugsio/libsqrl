use url::{Url, ParseError};
use std::collections::HashMap;

#[derive(Debug)]
pub struct SqrlUrl {
    pub original: String,
    pub url: Url,
    pub parsed_query: HashMap<String, String>,
}

impl SqrlUrl {
    pub fn parse(url: &str) -> SqrlUrl {
        let url = Url::parse(url).unwrap();
        let parsed_query = url::form_urlencoded::parse(url.query().unwrap().as_bytes()).into_owned().collect();

        SqrlUrl {
            original: url.to_string(),
            url: url,
            parsed_query: parsed_query,
        }
    }

    pub fn auth_domain(&self) -> String {
        let domain = self.url.host_str().unwrap().to_lowercase();
        match self.x() {
            Some(x) => format!("{}{}", domain, self.url.path().chars().take(x).collect::<String>()),
            _ => domain
        }
    }

    /// x query parameter, specifies the maximum extra path for auth_domain
    fn x(&self) -> Option<usize> {
        self.parsed_query.get("x").and_then(|i| usize::from_str_radix(i, 10).ok())
    }

    /// nut query parameter
    pub fn nut(&self) -> Option<&String> {
        //self.parsed_query.get("nut").map(|nut| nut.clone())
        self.parsed_query.get("nut")
    }

    /// cancel query parameter
    pub fn can(&self) -> Option<String> {
        self.parsed_query.get("can").map(|input|
            String::from_utf8(base64::decode_config(&input, base64::URL_SAFE).unwrap()).unwrap()
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_parses_auth_domain_examples() {
        // domain lowercased
        assert_eq!(super::SqrlUrl::parse("sqrl://ExAmPlE.cOm/?nut=...").auth_domain(), "example.com");
        // ignore port override
        assert_eq!(super::SqrlUrl::parse("sqrl://example.com:44344/?nut=...").auth_domain(), "example.com");
        // ignore username@m
        assert_eq!(super::SqrlUrl::parse("sqrl://jonny@example.com/?nut=...").auth_domain(), "example.com");
        // ignore user:pass@
        assert_eq!(super::SqrlUrl::parse("qrl://Jonny:Secret@example.com/?nut=...").auth_domain(), "example.com");
        // extend auth domain
        assert_eq!(super::SqrlUrl::parse("sqrl://example.com/jimbo/?x=6&nut=...").auth_domain(), "example.com/jimbo");
        // extension’s CASE and end extension at ‘?’ 
        assert_eq!(super::SqrlUrl::parse("sqrl://EXAMPLE.COM/JIMBO?x=16&nut=...").auth_domain(), "example.com/JIMBO");
        
        // TODO: what about ipv4 and ipv6
    }

    #[test]
    fn it_parses_the_nut() {
        // TODO: check the nut
        assert_eq!(super::SqrlUrl::parse("sqrl://EXAMPLE.COM/JIMBO?x=16&nut=...").nut(), Some(&"...".to_string()));
        assert_eq!(super::SqrlUrl::parse("sqrl://EXAMPLE.COM/JIMBO?x=16&nut=ailsdjfasjdflij42l2j4rl234jrl23rj").nut(), Some(&"ailsdjfasjdflij42l2j4rl234jrl23rj".to_string()));
    }

    #[test]
    fn it_parses_the_can() {
        // TODO: check the can parameter some more
        assert_eq!(super::SqrlUrl::parse("sqrl://EXAMPLE.COM/JIMBO?x=16&nut=...").can(), None);
        assert_eq!(super::SqrlUrl::parse("sqrl://EXAMPLE.COM/JIMBO?x=16&nut=...&can=aHR0cHM6Ly9zcXJsLmdyYy5jb20vZGVtbw").can(), Some("https://sqrl.grc.com/demo".to_string()));
    }

}
