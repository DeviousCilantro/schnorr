use rug::{Integer, rand};
use std::io;
use std::io::Write;
use sha2::{Digest, Sha256};

fn sign_message(sk: &Integer, message: &str, q: &Integer) -> (Integer, Integer) {
    let mut rand = rand::RandState::new();
    let mut k;
    loop {
        k = q.clone().random_below(&mut rand);
        if k != *sk {
            break;
        };
    };
    let r = Integer::from(2).pow_mod(&k, q).unwrap();
    let e = Integer::from_str_radix(&hash_message(&format!("{r}{message}")), 16).unwrap() % (q.clone() - Integer::from(1));
    let s = (k - e * sk.clone()) % (q - Integer::from(1));
    (r, s)
}

fn hash_message(message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(message);
    format!("{:x}", hasher.finalize())
}

fn main() {
    print!("Enter the plaintext: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let message = input.trim();
    print!("\nEnter the secret key: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let sk = Integer::from_str_radix(input, 10).unwrap();
    print!("\nEnter the modulus: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let q = Integer::from_str_radix(input, 10).unwrap();
    let (r, s) = sign_message(&sk, message, &q);
    println!("\nSignature: (r, s)");
    println!("r: {}", base64::encode(r.to_string()));
    println!("s: {}", base64::encode(s.to_string()));
}
