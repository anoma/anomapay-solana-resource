use std::io::Write;

use token_transfer_methods::{TOKEN_TRANSFER_GUEST_ELF, TOKEN_TRANSFER_GUEST_ID};

fn main() {
    let id_bytes: Vec<u8> = TOKEN_TRANSFER_GUEST_ID
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();

    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == "--dump-elf" {
        let path = args
            .get(2)
            .expect("Usage: transfer-circuit --dump-elf <output-path>");
        std::fs::write(path, TOKEN_TRANSFER_GUEST_ELF)
            .unwrap_or_else(|e| panic!("Failed to write ELF to {path}: {e}"));
        eprintln!("Wrote {} bytes to {path}", TOKEN_TRANSFER_GUEST_ELF.len());
    }

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "Image ID (hex): {}", hex::encode(&id_bytes)).unwrap();
    writeln!(stdout, "ELF size: {} bytes", TOKEN_TRANSFER_GUEST_ELF.len()).unwrap();
}
