// https://www.grc.com/sqrl/storage.htm
// https://github.com/Novators/libsqrl/blob/c/src/storage.c
// https://doc.rust-lang.org/book/ch03-02-data-types.html
// https://docs.rs/nom

use nom::{count, call, switch, do_parse, take, IResult, many0, many_m_n, complete};
use nom::combinator::peek;
use nom::number::streaming::{le_u8, le_u16, le_u32};

#[derive(Debug)]
pub struct S4 {
    pub blocks: Vec<Block>,
}

// TODO: The Vec's could maybe be arrays, but count_fixed was removed from nom 5
#[derive(Clone, Debug)]
pub enum Block {
    // Unrecognised type
    BlockTypeUnknown {
        length: u16,
        block_type: u16,
        data: Vec<u8>,
    },
    BlockType1 {
        // inclusive length of entire outer block 2 bytes
        length: u16,
        // type 1 = user access password protected data 2 bytes
        block_type: u16,
        // inclusive length of entire inner block 2 bytes
        pt_length: u16,
        // initialization vector for auth/encrypt 12 bytes
        aes_gcm_iv: Vec<u8>, // [u8; 12],
        // update for password change 16 bytes
        scrypt_random_salt: Vec<u8>, // [u8; 16],
        // memory consumption factor 1 byte
        scrypt_log_n_factor: u8,
        // time consumption factor 4 bytes
        scrypt_iteration_count: u32,
        // 16 binary flags 2 bytes
        option_flags: u16,
        // number of chars in hint 1 byte
        hint_length: u8,
        // seconds to run PW EnScrypt 1 byte
        pw_verify_sec: u8,
        // idle minutes before wiping PW 2 bytes
        idle_timeout_min: u16,
        // (IMK) 32 bytes
        encrypted_identity_master_key: Vec<u8>, // [u8; 32],
        // (ILK) 32 bytes
        encrypted_identity_lock_key: Vec<u8>, // [u8; 32],
        // 16 bytes
        verification_tag: Vec<u8>, // [u8; 16]
    },
    BlockType2 {
        length: u16,
        // type 2 = rescue code data 2 bytes
        block_type: u16,
        scrypt_random_salt: Vec<u8>, // [u8; 16],
        scrypt_log_n_factor: u8,
        scrypt_iteration_count: u32,
        encrypted_identity_unlock_key: Vec<u8>, // [u8; 32],
        // 16 bytes
        verification_tag: Vec<u8>, // [u8; 16]
    },
    BlockType3 {
        // length = 54, 86, 118 or 150. 2 bytes
        length: u16,
        // type 3 = previous identity unlock keys 2 bytes
        block_type: u16,
        // edition >= 1. count of all previous keys 2 bytes
        // edition was added 2016-04-21, might not be present
        edition: u16,
        // encrypted previous IUK 32 bytes
        // next old (if present) +32 bytes
        // more old (if present) +32 bytes
        // real old (if present) +32 bytes
        encrypted_previous_iuk: Vec<Vec<u8>>, // [u8; 32],
        // 16 bytes
        verification_tag: Vec<u8>, // [u8; 16]
    },
}

impl Block {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Block, ()> {
        do_parse!(
            input,
            length: le_u16 >>
            // block_type: call!(peek(le_u16)) >>
            data: switch!(call!(peek(le_u16)),
                          1 => call!(Self::block_type1, length) |
                          2 => call!(Self::block_type2, length) |
                          3 => call!(Self::block_type3, length) |
                          _ => call!(Self::block_unknown, length)
                    ) >>
            ( data )
        )
    }

    fn block_unknown(input: &[u8], length: u16) -> IResult<&[u8], Block, ()> {
        do_parse!(
            input,
            block_type: le_u16 >>
            // NOTE: data doesn't include length or block_type
            data: take!(length - 2 - 2) >>
            ( Block::BlockTypeUnknown {
                length: length,
                block_type: block_type,
                data: data.to_vec() }
            )
        )
    }

    fn block_type1(input: &[u8], length: u16) -> IResult<&[u8], Block, ()> {
        do_parse!(
            input,
            block_type: le_u16 >>
            pt_length: le_u16 >>
            aes_gcm_iv: count!(le_u8, 12) >>
            scrypt_random_salt: count!(le_u8, 16) >>
            scrypt_log_n_factor: le_u8 >>
            scrypt_iteration_count: le_u32 >>
            option_flags: le_u16 >>
            hint_length: le_u8 >>
            pw_verify_sec: le_u8 >>
            idle_timeout_min: le_u16 >>
            encrypted_identity_master_key: count!(le_u8, 32) >>
            encrypted_identity_lock_key: count!(le_u8, 32) >>
            verification_tag: count!(le_u8, 16) >>
            ( Block::BlockType1 {
                length, block_type, pt_length, aes_gcm_iv,
                scrypt_random_salt, scrypt_log_n_factor, scrypt_iteration_count,
                option_flags, hint_length, pw_verify_sec, idle_timeout_min,
                encrypted_identity_master_key, encrypted_identity_lock_key,
                verification_tag
            })
        )
    }

    fn block_type2(input: &[u8], length: u16) -> IResult<&[u8], Block, ()> {
        do_parse!(
            input,
            block_type: le_u16 >>
            scrypt_random_salt: count!(le_u8, 16) >>
            scrypt_log_n_factor: le_u8 >>
            scrypt_iteration_count: le_u32 >>
            encrypted_identity_unlock_key: count!(le_u8, 32) >>
            verification_tag: count!(le_u8, 16) >>
            ( Block::BlockType2 {
                length,
                block_type,
                scrypt_random_salt,
                scrypt_log_n_factor,
                scrypt_iteration_count,
                encrypted_identity_unlock_key,
                verification_tag
            })
        )
    }

    fn block_type3(input: &[u8], length: u16) -> IResult<&[u8], Block, ()> {
        do_parse!(
            input,
            block_type: le_u16 >>
            edition: le_u16 >>
            encrypted_previous_iuk: many_m_n!(1, 4, count!(le_u8, 32)) >>
            verification_tag: count!(le_u8, 16) >>
            ( Block::BlockType3 {
                length,
                block_type,
                edition,
                encrypted_previous_iuk,
                verification_tag
            })
        )
    }

    // TEMP: for crude testing purposes
    fn length(&self) -> u16 {
        match self {
            Block::BlockTypeUnknown { length, .. } => *length,
            Block::BlockType1 { length, .. } => *length,
            Block::BlockType2 { length, .. } => *length,
            Block::BlockType3 { length, .. } => *length,
        }
    }

    // TEMP: for crude testing purposes
    fn block_type(&self) -> u16 {
        match self {
            Block::BlockTypeUnknown { block_type, .. } => *block_type,
            Block::BlockType1 { block_type, .. } => *block_type,
            Block::BlockType2 { block_type, .. } => *block_type,
            Block::BlockType3 { block_type, .. } => *block_type,
        }
    }
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

    fn blocks(input: &[u8]) -> IResult<&[u8], Vec<Block>, ()> {
        do_parse!(
            input,
            blocks: many0!(complete!(Block::parse)) >>
            (blocks)
        )
    }

    // TODO: remove this
    pub fn enscrypted_password(&self, password: &[u8]) -> Vec<u8> {
        let mut enscrypted_password = vec![0u8, 32];
        for block in &self.blocks {
            // dbg!(block.clone());
            match block {
                //Block::BlockType1 { scrypt_random_salt, scrypt_log_n_factor, scrypt_iteration_count, aes_gcm_iv, encrypted_identity_master_key, encrypted_identity_lock_key, verification_tag, .. } => {
                Block::BlockType1 { 
                length, block_type, pt_length, aes_gcm_iv,
                scrypt_random_salt, scrypt_log_n_factor, scrypt_iteration_count,
                option_flags, hint_length, pw_verify_sec, idle_timeout_min,
                encrypted_identity_master_key, encrypted_identity_lock_key,
                verification_tag } => {
                    let params = scrypt::Params::new(*scrypt_log_n_factor, 256, 1).unwrap();
                    let mut output: Vec<u8> = vec![0u8; 32];
                    let mut result;
                    scrypt::scrypt(password, scrypt_random_salt, &params, &mut output).unwrap();
                    result = output.clone();

                    for _n in 1..*scrypt_iteration_count {
                        // println!("{:02x?}", &result);
                        scrypt::scrypt(password, &output.clone(), &params, &mut output).unwrap();
                        result.iter_mut().zip(output.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
                    }
                    // println!("{:02x?}", &result);
                    const BINARY: [u8; 356] =
                        [115, 113, 114, 108, 100, 97, 116, 97, 125, 0, 1, 0, 45, 0, 192, 52, 118, 104, 170, 33, 53,
                        69, 178, 164, 139, 254, 99, 164, 222, 81, 102, 228, 163, 246, 171, 112, 252, 12, 7, 214, 165,
                        164, 9, 4, 0, 0, 0, 241, 0, 4, 1, 15, 0, 238, 224, 209, 164, 16, 241, 168, 150, 113, 193, 73,
                        1, 227, 47, 126, 167, 149, 214, 188, 6, 224, 84, 194, 180, 218, 91, 231, 72, 15, 254, 16, 17,
                        227, 45, 170, 227, 160, 118, 29, 111, 229, 4, 85, 109, 171, 11, 140, 246, 81, 28, 142, 115,
                        26, 66, 121, 5, 223, 26, 150, 80, 202, 230, 119, 117, 33, 162, 184, 129, 72, 213, 226, 197,
                        95, 236, 103, 177, 27, 17, 5, 219, 73, 0, 2, 0, 162, 35, 43, 247, 123, 141, 243, 41, 97, 56,
                        124, 240, 148, 249, 159, 84, 9, 20, 0, 0, 0, 78, 119, 187, 192, 235, 17, 141, 74, 53, 3, 204,
                        108, 237, 94, 10, 218, 64, 233, 116, 170, 169, 30, 201, 135, 102, 147, 126, 233, 236, 142,
                        112, 183, 195, 252, 107, 165, 226, 244, 114, 172, 192, 182, 166, 126, 212, 5, 165, 125, 150,
                        0, 3, 0, 4, 0, 4, 18, 28, 173, 79, 150, 69, 44, 134, 241, 42, 53, 224, 139, 137, 185, 137,
                        129, 11, 239, 121, 65, 107, 61, 184, 56, 108, 219, 164, 227, 177, 64, 143, 151, 84, 129, 166,
                        191, 125, 10, 3, 252, 163, 34, 215, 182, 119, 140, 49, 126, 213, 240, 170, 162, 166, 55, 25,
                        28, 49, 105, 111, 131, 205, 139, 68, 32, 228, 65, 216, 11, 17, 37, 72, 25, 90, 248, 153, 123,
                        198, 167, 108, 181, 15, 229, 210, 173, 214, 189, 11, 200, 58, 83, 9, 55, 13, 155, 51, 239,
                        125, 186, 188, 203, 238, 201, 238, 189, 206, 31, 179, 229, 40, 234, 70, 172, 0, 44, 216, 44,
                        53, 24, 86, 247, 151, 168, 67, 60, 54, 185, 128, 50, 172, 247, 64, 6, 137, 124, 32, 169, 64,
                        251, 255, 186, 140, 4];
                    enscrypted_password = result;
                    sodiumoxide::init();
                    use sodiumoxide::crypto::aead::aes256gcm;
                    use std::convert::TryInto;
                    let aes = aes256gcm::Aes256Gcm::new().unwrap();
                    let nonce = aes256gcm::Nonce(aes_gcm_iv.as_slice().try_into().expect("nonce slice with incorrect length"));
                    let key = aes256gcm::Key(enscrypted_password.as_slice().try_into().expect("key slice with incorrect length"));
                    let tag = aes256gcm::Tag(verification_tag.as_slice().try_into().expect("tag slice with incorrect length"));
                    let data: Vec<u8> = BINARY[8..8+2+2+2+12+16+1+4+2+1+1+2].to_vec();
                    let mut decrypted: Vec<u8> = BINARY[8+2+2+2+12+16+1+4+2+1+1+2..8+2+2+2+12+16+1+4+2+1+1+2+32+32].to_vec();
                    println!("{}, {}", data.len(), decrypted.len());

                    //let mut decrypted = encrypted_identity_master_key.clone();
                    //decrypted.append(&mut encrypted_identity_lock_key.clone());
                    aes.open_detached(&mut decrypted, Some(&data), &tag, &nonce, &key).unwrap();
                    println!("{:?}", decrypted);
                },
                _ => ()
            };
        };

        enscrypted_password
    }
}

#[cfg(test)]
mod tests {
    const TEST_BINARY: [u8; 356] =
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
         172, 192, 182, 166, 126, 212, 5, 165, 125, 150, 0, 3, 0, 4, 0, 4, 18, 28, 173, 79, 150,
         69, 44, 134, 241, 42, 53, 224, 139, 137, 185, 137, 129, 11, 239, 121, 65, 107, 61, 184,
         56, 108, 219, 164, 227, 177, 64, 143, 151, 84, 129, 166, 191, 125, 10, 3, 252, 163, 34,
         215, 182, 119, 140, 49, 126, 213, 240, 170, 162, 166, 55, 25, 28, 49, 105, 111, 131, 205,
         139, 68, 32, 228, 65, 216, 11, 17, 37, 72, 25, 90, 248, 153, 123, 198, 167, 108, 181, 15,
         229, 210, 173, 214, 189, 11, 200, 58, 83, 9, 55, 13, 155, 51, 239, 125, 186, 188, 203,
         238, 201, 238, 189, 206, 31, 179, 229, 40, 234, 70, 172, 0, 44, 216, 44, 53, 24, 86, 247,
         151, 168, 67, 60, 54, 185, 128, 50, 172, 247, 64, 6, 137, 124, 32, 169, 64, 251, 255,
         186, 140, 4];
    const TEST_BASE64: &[u8] = b"\
        SQRLDATAfQABAC0AwDR2aKohNUWypIv-Y6TeUWbko_arcPwMB9alpAkEAAAA8QAEAQ8A7uDR\
        pBDxqJZxwUkB4y9-p5XWvAbgVMK02lvnSA_-EBHjLarjoHYdb-UEVW2rC4z2URyOcxpCeQXf\
        GpZQyuZ3dSGiuIFI1eLFX-xnsRsRBdtJAAIAoiMr93uN8ylhOHzwlPmfVAkUAAAATne7wOsR\
        jUo1A8xs7V4K2kDpdKqpHsmHZpN-6eyOcLfD_Gul4vRyrMC2pn7UBaV9lgADAAQABBIcrU-W\
        RSyG8So14IuJuYmBC-95QWs9uDhs26TjsUCPl1SBpr99CgP8oyLXtneMMX7V8KqipjcZHDFp\
        b4PNi0Qg5EHYCxElSBla-Jl7xqdstQ_l0q3WvQvIOlMJNw2bM-99urzL7snuvc4fs-Uo6kas\
        ACzYLDUYVveXqEM8NrmAMqz3QAaJfCCpQPv_uowE";

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

        assert_eq!(1, s4.blocks[0].block_type());
        assert_eq!(2, s4.blocks[1].block_type());
        assert_eq!(3, s4.blocks[2].block_type());

        assert_eq!(125, s4.blocks[0].length());
        assert_eq!(73, s4.blocks[1].length());
        assert_eq!(150, s4.blocks[2].length());
    }

    #[test]
    fn it_can_create_a_storage_from_base64_with_blocks() {
        let s4 = super::S4::new(&TEST_BASE64);
        assert_eq!(3, s4.blocks.len());

        assert_eq!(1, s4.blocks[0].block_type());
        assert_eq!(2, s4.blocks[1].block_type());
        assert_eq!(3, s4.blocks[2].block_type());

        assert_eq!(125, s4.blocks[0].length());
        assert_eq!(73, s4.blocks[1].length());
        assert_eq!(150, s4.blocks[2].length());
    }
}
