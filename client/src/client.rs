use std::{env, net::SocketAddr, sync::Arc};

use crate::key_log::KeyLogVec;
use anyhow::Result;
use rustls::{version::TLS13, ClientConfig, RootCertStore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use webpki::types::ServerName;

pub fn load_client_config(key_log: Arc<KeyLogVec>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        roots.add(cert).unwrap();
    }

    let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();

    config.key_log = key_log.clone();

    Arc::new(config)
}

async fn request(proxy: SocketAddr, data: &[u8]) -> Result<Vec<u8>> {
    let proxy_stream = TcpStream::connect(&proxy).await?;

    let key_log = Arc::new(KeyLogVec::new("clent_keylog"));
    let config = load_client_config(key_log);

    let connector = TlsConnector::from(config);
  //  let server_name = ServerName::try_from(env::var("HOST").unwrap()).expect("Invalid server name");
  let server_name = ServerName::try_from("www.rust-lang.org").expect("Invalid server name");
    let mut tls_stream = connector.connect(server_name, proxy_stream).await?;

    // write request
    tls_stream.write_all(data).await?;

    // read response
    let mut data = vec![];
    let mut buffer = [0u8; 4096];
    loop {
        let n = tls_stream.read(&mut buffer).await?;
        println!("n is {n}");
        if n == 0 {
            break;
        }
        data.extend(&buffer[..n]);
    }

    Ok(data)
}

#[cfg(test)]
mod test {
    use std::env;

    use super::request;

    // cargo test --package client --lib -- client::test::test_client_request --exact --show-output
    #[tokio::test]
    async fn test_client_request() {
        dotenv::dotenv().ok();
        let proxy_addr = env::var("PROXY_ADDR").unwrap();
        let content_length: usize = env::var("CONTENT_LENGTH").unwrap().parse().unwrap();

        let mut input = "what is your name?".to_string();
        let body_template = r#"{{"messages":[{{"role":"system","content":"you are a zypher girl!"}},{{"role":"user","content":"{}"}}],"model":"gpt-4o-mini","temperature":0.7}}"#;
        let padding = " ".repeat(content_length - body_template.len() - input.len() + 2);
        input.push_str(&padding);
        let body = body_template.replacen("{}", &input, 1);
        assert_eq!(body.len(), content_length);

        let msg = format!(
            "POST {} HTTP/1.1\r\n\
             Host:{}\r\n\
             Authorization:Bearer {}\r\n\
             Content-Type:application/json\r\n\
             Content-Length:{}\r\n\
             Connection:close\r\n\
             \r\n\
             {}",
            env::var("URL").unwrap(),
            env::var("HOST").unwrap(),
            env::var("OPENAI_API_KEY").unwrap(),
            env::var("CONTENT_LENGTH").unwrap(),
            body
        );

        let res = request(proxy_addr.parse().unwrap(), msg.as_bytes())
            .await
            .unwrap();
        println!("{}", String::from_utf8(res).unwrap());
    }

    // cargo test --package client --lib -- client::test::test_tmp --exact --show-output
    #[tokio::test]
    async fn test_tmp() {
        dotenv::dotenv().ok();
        let proxy_addr = env::var("PROXY_ADDR").unwrap();

        let msg = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes();

        let res = request(proxy_addr.parse().unwrap(), msg)
            .await
            .unwrap();
        println!("{}", String::from_utf8(res).unwrap());
    }
}
