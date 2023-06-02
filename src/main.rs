use rug::{Integer, rand};
use std::io;
use std::io::Write;
use sha2::{Digest, Sha256};
use num_primes::Generator;

fn generate_keys() -> (Integer, Integer, Integer) {
    let p = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let q: Integer = (p - Integer::from(1)) / 2;
    let mut rand = rand::RandState::new();
    let sk = q.clone().random_below(&mut rand);
    let pk = Integer::from(2).pow_mod(&sk, &q).unwrap();
    (pk, sk, q)
}

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

fn verify_message(pk: &Integer, message: &str, signature: (Integer, Integer), q: &Integer) {
    let (r, s) = signature;
    let e = Integer::from_str_radix(&hash_message(&format!("{r}{message}")), 16).unwrap() % (q.clone() - Integer::from(1));
    let v = (Integer::from(2).pow_mod(&s, q).unwrap() * pk.clone().pow_mod(&e, q).unwrap()) % q;
    assert_eq!(v, r, "Signature invalid.");
    println!("Signature valid.");
}

fn hash_message(message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(message);
    format!("{:x}", hasher.finalize())
}

fn main() {
    let (pk, sk, q) = generate_keys();
    print!("Enter a string: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let message = input.trim();
    let signature = sign_message(&sk, message, &q);
    println!("Signature: {signature:?}");
    verify_message(&pk, message, signature, &q);
}

