use std::io;

use rand::Rng;
use sha2::{Digest, Sha256};

fn main() {
    println!("username: ");
    let mut username = String::new();
    io::stdin()
        .read_line(&mut username)
        .expect("Failed to read line");
    println!("password: ");
    let mut password = String::new();
    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read line");

    let mut rng = rand::rng();

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let login = format!("{}:{}", username.trim(), password.trim());
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(login.as_bytes());
    let hash = hasher.finalize();
    println!("{}:{}", hex::encode(salt), hex::encode(hash));
}
