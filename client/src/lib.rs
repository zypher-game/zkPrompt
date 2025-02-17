pub mod client;
pub mod key_log;

#[cfg(test)]
mod tests {

    use ring::aead;
    use rustls::{
        crypto::{
            cipher::{make_tls13_aad, Nonce, PrefixedPayload},
            ring::{cipher_suite::TLS13_AES_128_GCM_SHA256, tls13::Tls13MessageEncrypter},
            tls13::OkmBlock,
        },
        tls13::key_schedule::{derive_traffic_iv, derive_traffic_key},
    };

    #[test]
    fn test_decrypter() {
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

        println!("nonce:{}", hex::encode(nonce.as_ref()));
        println!("add:{}", hex::encode(aad.as_ref()));

        // {
        //     let mut in_out = paypload.0.clone();
        //     let tag_offset = in_out.len().checked_sub(16).unwrap();
        //     let (in_out, received_tag) = in_out.split_at_mut(tag_offset);

        //     println!("in:{}", hex::encode(in_out.as_ref()));
        //     println!("tag:{}", hex::encode(received_tag.as_ref()));

        //     println!("tag:{:?}", received_tag.as_ref());
        // }

        encrypter
            .enc_key
            .open_in_place(nonce, aad, paypload.as_mut())
            .unwrap();

        println!("{}", String::from_utf8_lossy(paypload.as_ref()));
    }
}
