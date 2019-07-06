// https://www.grc.com/sqrl/storage.htm
// https://github.com/Novators/libsqrl/blob/c/src/storage.c
// https://doc.rust-lang.org/book/ch03-02-data-types.html
// https://docs.rs/nom

use nom::{do_parse, take, IResult, many0, complete};
use nom::number::streaming::le_u16;

pub struct S4 {
    pub blocks: Vec<BlockData>,
}

pub enum Block {
    Type1 {
        pt_length: u16,
        aes_gcm_iv: [u8; 12],
        scrypt_random_salt: [u8; 16],
        scrypt_log_n_factor: u8,
        scrypt_iteration_count: u32,
        option_flags: u16,
        hint_length: u8,
        pw_verify_sec: u8,
        idle_timeout_min: u16,
    },
}

#[derive(Clone)]
pub struct BlockData {
    pub length: u16,
    pub block_type: u16,
    pub data: Vec<u8>,
}

impl S4 {
    pub fn new(data: &[u8]) -> S4 {
        let data = &S4::decode_from_header(data);
        let blocks = S4::blocks(data).unwrap().1;
        S4 { blocks }
    }

    fn decode_from_header(data: &[u8]) -> Vec<u8> {
        match S4::signature(&data) {
            Ok((binary, b"sqrldata")) => binary.to_vec(),
            Ok((base64, b"SQRLDATA")) => S4::base64url_to_binary(&base64),
            _ => panic!("Not a valid SQRL header"),
        }
    }

    fn signature(input: &[u8]) -> IResult<&[u8], &[u8], ()> {
        take!(input, 8)
    }

    fn base64url_to_binary(input: &[u8]) -> Vec<u8> {
        // To aid in the exchange of SQRL data during development — posting on forums, etc. —
        // base64url-illegal line ending and whitespace characters — CR, LF, TAB and SPACE —
        // should be silently ignored for line wrap tolerance.
        let input: Vec<u8> = input.to_vec()
            .into_iter()
            .filter(|b| !b"\n\r\t \x0b\x0c".contains(b))
            .collect();
        base64::decode_config(&input, base64::URL_SAFE).unwrap()
    }

    fn blocks(input: &[u8]) -> IResult<&[u8], Vec<BlockData>, ()> {
        do_parse!(
            input,
            blocks: many0!(complete!(S4::block)) >>
            (blocks)
        )
    }

    fn block(input: &[u8]) -> IResult<&[u8], BlockData, ()> {
        do_parse!(
            input,
            length: le_u16 >>
            block_type: le_u16 >>
            data: take!(length - 4) >>
            ( BlockData {
                length: length,
                block_type: block_type,
                data: data.to_vec() }
            )
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_can_create_a_storage_from_binary_without_blocks() {
        let s4 = super::S4::new(b"sqrldata");
        assert_eq!(0, s4.blocks.len());
    }

    #[test]
    fn it_can_create_a_storage_from_base64_without_blocks() {
        let s4 = super::S4::new(b"SQRLDATA");
        assert_eq!(0, s4.blocks.len());
    }
}
