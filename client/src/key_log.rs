use std::sync::Mutex;

use rustls::KeyLog;

#[derive(Debug, PartialEq)]
pub struct KeyLogItem {
    pub label: String,
    pub client_random: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Debug)]
pub struct KeyLogVec {
    pub label: &'static str,
    pub items: Mutex<Vec<KeyLogItem>>,
}

impl KeyLogVec {
    pub fn new(who: &'static str) -> Self {
        Self {
            label: who,
            items: Mutex::new(vec![]),
        }
    }

    pub fn take(&self) -> Vec<KeyLogItem> {
        std::mem::take(&mut self.items.lock().unwrap())
    }
}

impl KeyLog for KeyLogVec {
    fn log(&self, label: &str, client: &[u8], secret: &[u8]) {
        let value = KeyLogItem {
            label: label.into(),
            client_random: client.into(),
            secret: secret.into(),
        };

        self.items.lock().unwrap().push(value);
    }
}
