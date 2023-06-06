use rug::Integer;
use num_primes::Generator;
use ring::rand::{SystemRandom, SecureRandom};

fn generate_keypair() -> (String, String, String) {
    let rand = SystemRandom::new();
    println!("\nGenerating keypair...");
    let p = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let q: Integer = (p.clone() - Integer::from(1)) / 2;
    let mut h;
    loop {
        h = random_integer(&rand, p.clone());
        if ((h.clone() * h.clone()) - 1) % p.clone() != 0 {
            break;
        }
    }
    let sk = random_integer(&rand, q.clone());
    let pk = Integer::from(2).pow_mod(&sk, &q).unwrap();
    (base64::encode(pk.to_string()), base64::encode(sk.to_string()), base64::encode(q.to_string()))
}

fn random_integer(rng: &SystemRandom, range: Integer) -> Integer {
    loop {
        let mut bytes = vec![0; ((range.significant_bits() + 7) / 8) as usize];
        rng.fill(&mut bytes).unwrap();
        let num = Integer::from_digits(&bytes, rug::integer::Order::Lsf);
        if num < range {
            return num;
        }
    }
}

fn main() {
    let (pk, sk, q) = generate_keypair();
    println!("\nPublic key: {pk}");
    println!("\nSecret key: {sk}");
    println!("\nModulus: {q}");
}

