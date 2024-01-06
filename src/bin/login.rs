use std::io;

use rand::Rng;
use sha2::{Sha256, Digest};


fn main() {
    println!("username: ");
    let mut username = String::new();
    io::stdin().read_line(&mut username).expect("Failed to read line");
    println!("password: ");
    let mut password = String::new();
    io::stdin().read_line(&mut password).expect("Failed to read line");

    let mut rng = rand::thread_rng();

    let salt = rng.gen::<[u8; 16]>();

    let login = format!("{}:{}", username.trim(), password.trim());
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(login.as_bytes());
    let hash = hasher.finalize();
    println!("{}:{}", hex::encode(salt), hex::encode(hash));
}
