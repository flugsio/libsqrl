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
    const TEST_BINARY: [u8; 354] =
        [115, 113, 114, 108, 100, 97, 116, 97, 125, 0, 1, 0, 45, 0, 192, 52, 118, 104, 170, 33,
         53, 69, 178, 164, 139, 254, 99, 164, 222, 81, 102, 228, 163, 246, 171, 112, 252, 12, 7,
         214, 165, 164, 9, 4, 0, 0, 0, 241, 0, 4, 1, 15, 0, 238, 224, 209, 164, 16, 241, 168, 150,
         113, 193, 73, 1, 227, 47, 126, 167, 149, 214, 188, 6, 224, 84, 194, 180, 218, 91, 231,
         72, 15, 254, 16, 17, 227, 45, 170, 227, 160, 118, 29, 111, 229, 4, 85, 109, 171, 11, 140,
         246, 81, 28, 142, 115, 26, 66, 121, 5, 223, 26, 150, 80, 202, 230, 119, 117, 33, 162,
         184, 129, 72, 213, 226, 197, 95, 236, 103, 177, 27, 17, 5, 219, 73, 0, 2, 0, 162, 35, 43,
         247, 123, 141, 243, 41, 97, 56, 124, 240, 148, 249, 159, 84, 9, 20, 0, 0, 0, 78, 119,
         187, 192, 235, 17, 141, 74, 53, 3, 204, 108, 237, 94, 10, 218, 64, 233, 116, 170, 169,
         30, 201, 135, 102, 147, 126, 233, 236, 142, 112, 183, 195, 252, 107, 165, 226, 244, 114,
         172, 192, 182, 166, 126, 212, 5, 165, 125, 148, 0, 3, 0, 4, 18, 28, 173, 79, 150, 69, 44,
         134, 241, 42, 53, 224, 139, 137, 185, 137, 129, 11, 239, 121, 65, 107, 61, 184, 56, 108,
         219, 164, 227, 177, 64, 143, 151, 84, 129, 166, 191, 125, 10, 3, 252, 163, 34, 215, 182,
         119, 140, 49, 126, 213, 240, 170, 162, 166, 55, 25, 28, 49, 105, 111, 131, 205, 139, 68,
         32, 228, 65, 216, 11, 17, 37, 72, 25, 90, 248, 153, 123, 198, 167, 108, 181, 15, 229,
         210, 173, 214, 189, 11, 200, 58, 83, 9, 55, 13, 155, 51, 239, 125, 186, 188, 203, 238,
         201, 238, 189, 206, 31, 179, 229, 40, 234, 70, 172, 0, 44, 216, 44, 53, 24, 86, 247, 151,
         168, 67, 60, 54, 185, 128, 50, 172, 247, 64, 6, 137, 124, 32, 169, 64, 251, 255, 186,
         140, 4];
    const TEST_BASE64: &[u8] = b"\
        SQRLDATAfQABAC0Abouu7IvEI_1qknlaakonT7Lm4PWRwle2tKfXMQkEAAAA8QAEAQ8Au7C0\
        -pN8wxqzf-Qx0XUTZMXq3dS7brDwEaBTdwqsRkKi-mE_mV9UVHCe6sj1kMTYrqPsDNflap_j\
        D_K5-8_dMPLoB0pnbp9MqPXuzlXEe5dJAAIAUWdkk7EVnS3BwXMVJkUU7AnoAAAA6bvMz939\
        Yf_CkJTcd7tPg9qecHjC5n4tcnjO1PP5yqpEHr9C7SxCZ0cQ-UcdhAVmlAADAKz22QR9avOQ\
        MyOEJ3V6G_f3uhLgtg-T3_DNONeWVlI7PZcYwYsY_aDc_ZcpBb4L91Dv5xBtPgN2owc93O9O\
        lSr0Rhs8unMNgDy809SomAnlHrTz6oOg6Y-Cz8glP5kRcC8RpTIQugCCr8KkvhzEgydtC4aD\
        MlFn3qqzykp8NkL3QJUPoENfba3N4KZA8jbzpw";

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

    #[test]
    fn it_can_create_a_storage_from_binary_with_blocks() {
        let s4 = super::S4::new(&TEST_BINARY);
        assert_eq!(3, s4.blocks.len());

        assert_eq!(1, s4.blocks[0].block_type);
        assert_eq!(2, s4.blocks[1].block_type);
        assert_eq!(3, s4.blocks[2].block_type);

        assert_eq!(125, s4.blocks[0].length);
        assert_eq!(73, s4.blocks[1].length);
        assert_eq!(148, s4.blocks[2].length);
    }

    #[test]
    fn it_can_create_a_storage_from_base64_with_blocks() {
        let s4 = super::S4::new(&TEST_BASE64);
        assert_eq!(3, s4.blocks.len());

        assert_eq!(1, s4.blocks[0].block_type);
        assert_eq!(2, s4.blocks[1].block_type);
        assert_eq!(3, s4.blocks[2].block_type);

        assert_eq!(125, s4.blocks[0].length);
        assert_eq!(73, s4.blocks[1].length);
        assert_eq!(148, s4.blocks[2].length);
    }
}
