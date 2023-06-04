use rug::{Integer, rand};
use num_primes::Generator;

fn generate_keypair() -> (String, String, String) {
    println!("\nGenerating keypair...");
    let p = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let q: Integer = (p - Integer::from(1)) / 2;
    let mut rand = rand::RandState::new();
    let sk = q.clone().random_below(&mut rand);
    let pk = Integer::from(2).pow_mod(&sk, &q).unwrap();
    (base64::encode(pk.to_string()), base64::encode(sk.to_string()), base64::encode(q.to_string()))
}

fn main() {
    let (pk, sk, q) = generate_keypair();
    println!("\nPublic key: {pk}");
    println!("\nSecret key: {sk}");
    println!("\nModulus: {q}");
}

