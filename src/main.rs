use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;

/// ------------------------------
/// Aviso: implementação didática.
/// Sem padding seguro (OAEP), não use em produção.
/// ------------------------------

fn modinv(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    // Inverso modular via algoritmo estendido de Euclides (forma iterativa)
    let mut mn = (m.clone(), a.mod_floor(m));
    let mut xy = (BigInt::zero(), BigInt::one());
    let mut last_xy = (BigInt::one(), BigInt::zero());

    while mn.1 != BigInt::zero() {
        let q = &mn.0 / &mn.1;
        mn = (mn.1.clone(), &mn.0 - &q * &mn.1);

        let tmp = xy.clone();
        xy = (&last_xy.0 - &q * &xy.0, &last_xy.1 - &q * &xy.1);
        last_xy = tmp;
    }

    if mn.0 != BigInt::one() {
        return None; // não há inverso se gcd != 1
    }

    let mut result = last_xy.1;
    if result.sign() == num_bigint::Sign::Minus {
        result += m;
    }
    Some(result)
}

fn is_probably_prime(n: &BigUint, k_rounds: u32) -> bool {
    // Miller-Rabin probabilístico (didático)
    if *n < BigUint::from(2u32) {
        return false;
    }
    if *n == BigUint::from(2u32) || *n == BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // escreve n-1 = d * 2^r
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let n_minus_one = n - &one;

    let mut d = n_minus_one.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let mut rng = OsRng;
    'witness_loop: for _ in 0..k_rounds {
        // escolhe a em [2, n-2]
        let a = rng.gen_biguint_below(&(n - &two)) + &two;
        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_one {
            continue 'witness_loop;
        }

        for _ in 0..(r - 1) {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'witness_loop;
            }
        }
        return false; // composto
    }
    true // provavelmente primo
}

fn random_prime(bits: usize) -> BigUint {
    let one = BigUint::one();
    let top_bit = &one << (bits - 1);

    let mut rng = OsRng;
    loop {
        // número aleatório do tamanho pedido
        let mut candidate = rng.gen_biguint(bits as u64);
        // garante bit mais significativo ligado (tamanho) e ímpar
        candidate |= &top_bit;
        candidate |= &one;

        if is_probably_prime(&candidate, 16) {
            return candidate;
        }
    }
}

#[derive(Debug, Clone)]
struct RsaKeys {
    n: BigUint,
    e: BigUint,
    d: BigUint,
}

fn generate_keys(bits: usize) -> RsaKeys {
    // gera p e q ~bits/2 cada
    let p = random_prime(bits / 2);
    let mut q = random_prime(bits / 2);
    while q == p {
        q = random_prime(bits / 2);
    }

    let n = &p * &q;
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());

    let e = BigUint::from(65537u32);
    // confere se gcd(e, phi) == 1
    assert!(
        e.gcd(&phi) == BigUint::one(),
        "gcd(e, phi) != 1 — gere novamente"
    );

    let e_i = e.to_bigint().unwrap();
    let phi_i = phi.to_bigint().unwrap();
    let d = modinv(&e_i, &phi_i)
        .expect("não foi possível calcular inverso modular")
        .to_biguint()
        .expect("d negativo?!");

    RsaKeys { n, e, d }
}

fn encrypt_message(msg: &str, e: &BigUint, n: &BigUint) -> BigUint {
    let m = BigUint::from_bytes_be(msg.as_bytes());
    assert!(
        m < *n,
        "Mensagem grande demais para um bloco; reduza a mensagem ou aumente o tamanho da chave."
    );
    m.modpow(e, n)
}

fn decrypt_message(cipher: &BigUint, d: &BigUint, n: &BigUint) -> String {
    let m = cipher.modpow(d, n);
    let bytes = m.to_bytes_be();
    String::from_utf8(bytes).unwrap_or_else(|_| "<bytes inválidos>".to_string())
}

fn main() {
    // *** tamanho de chave didático: 1024 bits (rápido). Para testes maiores, use 2048.
    let bits = 1024;
    println!("Gerando chaves RSA {}-bit (didático)...", bits);
    let keys = generate_keys(bits);

    // Mostra chaves em hexadecimal
    println!("n (hex) = {}", keys.n.to_str_radix(16));
    println!("e (hex) = {}", keys.e.to_str_radix(16));
    println!("d (hex) = {}", keys.d.to_str_radix(16));

    // Exemplo de uso
    let mensagem = "Olá RSA no Rust (didático)!";
    println!("\nMensagem original: {}", mensagem);

    let cifrado = encrypt_message(mensagem, &keys.e, &keys.n);
    println!("Cifrado (hex): {}", cifrado.to_str_radix(16));

    let decifrado = decrypt_message(&cifrado, &keys.d, &keys.n);
    println!("Decifrado: {}", decifrado);
}
