pub mod client;
pub mod key_log;

#[cfg(test)]
mod tests {

    use ring::aead;
    use rustls::{
        crypto::{
            cipher::{make_tls13_aad, Nonce, PrefixedPayload},
            ring::{
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                tls13::{Tls13MessageEncrypter, TLS13_CHACHA20_POLY1305_SHA256},
            },
            tls13::OkmBlock,
        },
        tls13::key_schedule::{derive_traffic_iv, derive_traffic_key},
    };

    #[test]
    fn test_aes_gcm() {
        let secret_bytes =
            hex::decode("4164bcc581ef89891256d9a7752205fb1c0504920eaa027acb5b9085033933a7")
                .unwrap();
        let secret = OkmBlock::new(&secret_bytes);

        let suite = TLS13_AES_128_GCM_SHA256.tls13().unwrap();

        let expander = suite.hkdf_provider.expander_for_okm(&secret);
        let key = derive_traffic_key(expander.as_ref(), suite.aead_alg);
        let iv = derive_traffic_iv(expander.as_ref());

        let encrypter = Tls13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_128_GCM, key.as_ref()).unwrap(),
            ),
            iv,
        };

        let mut paypload = {
            let  bytes  = hex::decode("000000000047b53945ae6d1b7dabccb67859367520bf8634e790f704be14aa14e7a83553c33d23c946e5de5f80685f2b0dcd1ab9f264a17a8ac89d92bade90c129887b36bfe8b0718ef96ed79dcbc5dc6ff29f2cd652f748b5e42fcc4c1e245594de4ad219d1b6f91e5f5c79bcfe2b").unwrap();
            PrefixedPayload(bytes)
        };
        let aad = aead::Aad::from(make_tls13_aad(paypload.len()));

        let seq = 0;
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&encrypter.iv, seq).0);
        let nonce_copy = nonce.as_ref().to_vec();
        let mut ct_copy = paypload.0.clone();

        encrypter
            .enc_key
            .open_in_place(nonce, aad, paypload.as_mut())
            .unwrap();

        let tag_offset = ct_copy.len().checked_sub(16).unwrap();
        let (ct, received_tag_0) = ct_copy.split_at_mut(tag_offset);
        let (pt, received_tag_1) = paypload.0.split_at_mut(tag_offset);
        assert_eq!(received_tag_0, received_tag_1);
        println!("key:{}", hex::encode(key.as_ref()));
        println!("nonce:{}", hex::encode(nonce_copy));
        println!("add:{}", hex::encode(aad.as_ref()));
        println!("ct:{}", hex::encode(ct.as_ref()));
        println!("tag:{}", hex::encode(received_tag_0.as_ref()));
        println!("pt:{}",hex::encode(pt.as_ref()) );
        println!("pt_len:{}",pt.as_ref().len() );


        {
            println!("ct:{:?}", ct.as_ref());
            println!("ct:{:?}", [71, 181, 57, 69, 174, 109, 27, 125, 171, 204, 182, 120, 89, 54, 117, 32, 191, 134, 52, 231, 144, 247, 4, 190, 20, 170, 20, 231, 168, 53, 83, 195, 61, 35, 201, 70, 229, 222, 95, 128, 104, 95, 43, 13, 205, 26, 185, 242, 100, 161, 122, 138, 200, 157, 146, 186, 222, 144, 193, 41, 136, 123, 54, 191, 232, 176, 113, 142, 249, 110, 215, 157, 203, 197, 220, 111, 242, 159, 44, 214].len());
        }
    }

    #[test]
    fn test_chacha20_poly1305() {
        let secret_bytes =
            hex::decode("ac49f185f79856dad7a170ce8acc3f297229f6392ce3b107e30a560b23922cca")
                .unwrap();
        let secret = OkmBlock::new(&secret_bytes);

        let suite = TLS13_CHACHA20_POLY1305_SHA256.tls13().unwrap();

        let expander = suite.hkdf_provider.expander_for_okm(&secret);
        let key = derive_traffic_key(expander.as_ref(), suite.aead_alg);

        let iv = derive_traffic_iv(expander.as_ref());

        let encrypter = Tls13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key.as_ref()).unwrap(),
            ),
            iv,
        };

        let mut paypload = {
            let  bytes  = hex::decode("0000000000546f6d6f72726f772077696c6c20626520626574746572212121212121212121546f6d6f72726f772077696c6c20626520626574746572212121212121212121").unwrap();
            PrefixedPayload(bytes)
        };
        let aad = aead::Aad::from(make_tls13_aad(paypload.len()));

        let seq = 0;
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&encrypter.iv, seq).0);
        let nonce_copy = nonce.as_ref().to_vec();

        let _tag = encrypter
            .enc_key
            .seal_in_place_separate_tag(nonce, aad, paypload.as_mut())
            .unwrap();

        println!("key:{}", hex::encode(key.as_ref()));
        println!("nonce:{}", hex::encode(nonce_copy));
        println!("ct:{}", hex::encode(paypload.as_ref()));
    }
}
