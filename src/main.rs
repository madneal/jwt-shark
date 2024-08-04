use base64::prelude::*;
use clap::{Arg, Command};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

#[derive(Serialize, Deserialize)]
struct Header {
    typ: String,
    alg: String,
}

struct Token {
    header: String,
    payload: String,
    signature: Vec<u8>,
}

fn main() {
    let matches = Command::new("JWT Cracker")
        .arg(
            Arg::new("concurrency")
                .short('c')
                .default_value("10")
                .help("Set concurrent workers"),
        )
        .arg(
            Arg::new("token_file")
                .short('t')
                .required(true)
                .help("File containing JWT token(s)"),
        )
        .arg(
            Arg::new("dict_file")
                .short('d')
                .help("Dictionary file. If omitted, will read from stdin"),
        )
        .get_matches();

    let worker_count: usize = matches
        .get_one::<String>("concurrency")
        .unwrap()
        .parse()
        .expect("Invalid number of workers");
    let token_file = matches.get_one::<String>("token_file").unwrap();
    let dict_file = matches.get_one::<String>("dict_file");

    let input_lines = if let Some(dict_file) = dict_file {
        let file = File::open(dict_file).expect("Failed to open dict file");
        BufReader::new(file).lines().collect::<Result<Vec<_>, _>>().expect("Failed to read lines from dict file")
    } else {
        let stdin = io::stdin();
        stdin.lock().lines().collect::<Result<Vec<_>, _>>().expect("Failed to read lines from stdin")
    };

    let file = File::open(token_file).expect("Failed to open token file");
    let mut s = BufReader::new(file).lines();
    if let Some(Ok(t)) = s.next() {
        crack_jwt(&t, worker_count, input_lines);
    }
}

fn crack_jwt(
    token: &str,
    worker_count: usize,
    input_lines: Vec<String>,
) {
    let (tx, rx) = mpsc::channel();
    let rx = Arc::new(Mutex::new(rx));
    let token = Arc::new(parse_token(token));

    let mut handles = vec![];

    for _ in 0..worker_count {
        let rx = Arc::clone(&rx);
        let token = Arc::clone(&token);
        let handle = thread::spawn(move || {
            while let Ok(secret) = rx.lock().unwrap().recv() {
                let header_payload = format!("{}.{}", token.header, token.payload);
                if check_signature(&secret, header_payload.as_bytes(), &token.signature) {
                    println!("{}    {}", secret, header_payload);
                    std::process::exit(0);
                }
            }
        });
        handles.push(handle);
    }

    for secret in input_lines {
        tx.send(secret).expect("Failed to send secret");
    }

    drop(tx);
    for handle in handles {
        handle.join().expect("Failed to join thread");
    }
}

fn check_signature(secret: &str, header_payload: &[u8], valid_signature: &[u8]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("Failed to create HMAC");
    mac.update(header_payload);
    mac.finalize().into_bytes().as_slice() == valid_signature
}

fn parse_token(token: &str) -> Token {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        eprintln!("Invalid token");
        std::process::exit(1);
    }

    let header = parts[0];
    let decoded_header = BASE64_URL_SAFE_NO_PAD
        .decode(header)
        .expect("Failed to decode header");
    let h: Header = serde_json::from_slice(&decoded_header).expect("Failed to parse header");

    if h.typ != "JWT" {
        eprintln!("Invalid token type");
        std::process::exit(1);
    }

    if h.alg != "HS256" {
        eprintln!("Currently only HS256 is supported");
        std::process::exit(1);
    }

    let base64_sig = parts[2];
    let signature = BASE64_URL_SAFE_NO_PAD
        .decode(base64_sig)
        .expect("Failed to decode signature");

    Token {
        header: parts[0].to_string(),
        payload: parts[1].to_string(),
        signature,
    }
}