// Test fixtures for Rust security rules
// DO NOT use as templates!

use std::fs;

fn hardcoded_secrets() {
    let password = "SuperSecret123!";
    let api_key = "sk_live_abcdef1234567890";
    let aws_key = "AKIAIOSFODNN7EXAMPLE";
}

fn debug_statements() {
    println!("DEBUG: starting process");
    eprintln!("Error: {:?}", error);
    dbg!(variable);
}

fn unsafe_file_access(filename: &str) -> Result<String, std::io::Error> {
    let content = fs::read_to_string(filename)?;
    Ok(content)
}

fn weak_crypto() {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
}

fn command_injection() {
    use std::process::Command;
    let output = Command::new("sh")
        .arg("-c")
        .arg(user_input)
        .output();
}
