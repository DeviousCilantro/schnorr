use rug::Integer;
use std::io;
use std::io::Write;
use sha2::{Digest, Sha256};

fn verify_message(pk: &Integer, message: &str, signature: (Integer, Integer), q: &Integer) {
    let (r, s) = signature;
    let e = Integer::from_str_radix(&hash_message(&format!("{r}{message}")), 16).unwrap() % (q.clone() - Integer::from(1));
    let v = (Integer::from(2).pow_mod(&s, q).unwrap() * pk.clone().pow_mod(&e, q).unwrap()) % q;
    assert_eq!(v, r, "Signature invalid.");
    println!("\nSignature valid.");
}

fn hash_message(message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(message);
    format!("{:x}", hasher.finalize())
}

fn main() {
    print!("Enter the message: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let message = input.trim();
    print!("\nEnter the signature (r, s): ");
    print!("\nEnter r: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let r = Integer::from_str_radix(input, 10).unwrap();
    print!("\nEnter s: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let s = Integer::from_str_radix(input, 10).unwrap();
    print!("\nEnter the public key: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let pk = Integer::from_str_radix(input, 10).unwrap();
    print!("\nEnter the modulus: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let q = Integer::from_str_radix(input, 10).unwrap();
    let signature = (r, s);
    verify_message(&pk, message, signature, &q);
}

