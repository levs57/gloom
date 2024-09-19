use std::{env, fs::{self, File}, io::{Read, Write}, path::{Path, PathBuf}, process, sync::mpsc::{self, Receiver}, thread::{self, sleep}, time::Duration};

use base32::Alphabet;
use crossterm::event::{Event, KeyCode, KeyEvent};

use cocoon::{MiniCocoon};
use rpassword::read_password;
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroize;

fn unseal(_vault_name: &str) -> ! {
    let mut vault_name = PathBuf::new();
    vault_name.push(_vault_name);
    if let None = vault_name.extension() {
        vault_name.set_extension("vault");
    }
    if ! vault_name.exists() {
        println!("Vault not found.");
        std::process::exit(1)
    }
    
    let mut vault_file = File::open(vault_name).unwrap();
    let mut encrypted_vault = Vec::new();
    vault_file.read_to_end(&mut encrypted_vault).unwrap();
    
    let seed = hex::decode("c8977f757babb1766fec969a321d3fb058d037b435da0d1a6c2798bd8d890733").unwrap(); 
    // sha256 of "gloom totp"

    println!("Please, enter your password:");
    std::io::stdout().flush().unwrap();
    let mut tmp = read_password().unwrap();
    let mut pwd_trimmed = tmp.trim().to_string();
    tmp.zeroize();
    let password = pwd_trimmed.as_bytes();
    let mut cocoon = MiniCocoon::from_password(password, &seed);
    pwd_trimmed.zeroize();

    let mut secret_bytes = cocoon.unwrap(&encrypted_vault).unwrap_or_else(|_| {
        println!("Password incorrect, decryption failed.");
        std::process::exit(1)
    });

    let mut secret = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);
    
    secret_bytes.zeroize();

    println!("{}", secret);

    secret.zeroize();
    std::process::exit(0)


}

fn read_otp_codes(_vault_name: &str) -> ! {
    let mut vault_name = PathBuf::new();
    vault_name.push(_vault_name);
    if let None = vault_name.extension() {
        vault_name.set_extension("vault");
    }

    if ! vault_name.exists() {
        println!("Vault not found.");
        std::process::exit(1)
    }

    let mut vault_file = File::open(vault_name).unwrap();
    let mut encrypted_vault = Vec::new();
    vault_file.read_to_end(&mut encrypted_vault).unwrap();
    
    let seed = hex::decode("c8977f757babb1766fec969a321d3fb058d037b435da0d1a6c2798bd8d890733").unwrap(); 
    // sha256 of "gloom totp"

    println!("Please, enter your password:");
    std::io::stdout().flush().unwrap();
    let mut tmp = read_password().unwrap();
    let mut pwd_trimmed = tmp.trim().to_string();
    tmp.zeroize();
    let password = pwd_trimmed.as_bytes();
    let mut cocoon = MiniCocoon::from_password(password, &seed);
    pwd_trimmed.zeroize();

    let secret = cocoon.unwrap(&encrypted_vault).unwrap_or_else(|_| {
        println!("Password incorrect, decryption failed.");
        std::process::exit(1)
    });

    println!("Generating OTP codes, press q to exit.");
    let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret);

    let mut token = String::new();
    loop {
        let tmp = totp.generate_current().unwrap();
        if tmp != token {
            token = tmp;
            println!("{}", token);
        }
        crossterm::terminal::enable_raw_mode().unwrap();
        if crossterm::event::poll(Duration::from_millis(500)).unwrap() {
            let keypress = crossterm::event::read();
            match keypress.unwrap() {
                Event::Key(KeyEvent {
                    code: KeyCode::Char('q'),
                    ..
                }) => {
                    crossterm::terminal::disable_raw_mode().unwrap();
                    drop(cocoon);
                    drop(totp);
                    std::process::exit(0);
                },
                _ => {},
            }
        };
        crossterm::terminal::disable_raw_mode().unwrap();
    }

}

fn add_vault(_vault_name: &str) -> ! {
    println!("Please, enter your password:");
    std::io::stdout().flush().unwrap();
    let mut tmp = read_password().unwrap();
    println!("Please, repeat your password:");
    std::io::stdout().flush().unwrap();
    let mut tmp2 = read_password().unwrap();
    if tmp != tmp2 {
        println!("Passwords do not coincide.");
        tmp.zeroize();
        tmp2.zeroize();
        std::process::exit(1);
    }
    tmp2.zeroize();
    let mut pwd_trimmed = tmp.trim().to_string();
    tmp.zeroize();
    let password = pwd_trimmed.as_bytes();
    let seed = hex::decode("c8977f757babb1766fec969a321d3fb058d037b435da0d1a6c2798bd8d890733").unwrap(); 
    // sha256 of "gloom totp"
    let mut cocoon = MiniCocoon::from_password(password, &seed);
    pwd_trimmed.zeroize();

    println!("Please, input your secret TOTP code:");
    std::io::stdout().flush().unwrap();
    let mut _secret_str = String::new();
    std::io::stdin().read_line(&mut _secret_str).unwrap();
    let mut secret_str = _secret_str.trim().to_string();
    _secret_str.zeroize();
    let mut secret_bytes = Secret::Encoded(secret_str).to_bytes().unwrap_or_else(|_|{
        println!("Invalid secret code.");
        std::process::exit(1);
    });
    let encrypted_secret = cocoon.wrap(&secret_bytes).unwrap();
    secret_bytes.zeroize();

    let mut vault_name = PathBuf::new();
    vault_name.push(_vault_name);
    if let None = vault_name.extension() {
        vault_name.set_extension("vault");
    }

    let mut file = File::create(vault_name).unwrap();
    file.write_all(&encrypted_secret).unwrap();

    std::process::exit(0);

}

fn invalid_input() -> ! {
    println!("Available commands:");
    println!("gloom add vaultname : create totp vault");
    println!("gloom otp vaultname : read otp codes from the vault");
    println!("gloom unseal vaultname : reveal root secret");
    std::process::exit(1);
}

fn main() {

    let args : Vec<_> = std::env::args().collect();

    if args.len() != 3 {
        invalid_input()
    }

    let command = &args[1];
    let vault_name = &args[2];

    if command == "otp" {
        read_otp_codes(&vault_name)
    }

    if command == "add" {
        add_vault(&vault_name)
    }

    if command == "unseal" {
        unseal(&vault_name)
    }

    invalid_input()
}
