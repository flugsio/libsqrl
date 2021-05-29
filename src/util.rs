use sodiumoxide::base64 as sodium_base64;
use sodiumoxide::base64::Variant::UrlSafeNoPadding;

pub(crate) fn encode64<T: AsRef<[u8]>>(bin: T) -> String {
    sodium_base64::encode(bin, UrlSafeNoPadding).to_string()
}

pub(crate) fn decode64<T: AsRef<[u8]>>(b64: T) -> String {
    //String::from_utf8(base64::decode_config(b64, base64::URL_SAFE).unwrap()).unwrap()
    String::from_utf8(sodium_base64::decode(b64, UrlSafeNoPadding).unwrap()).unwrap()
}
