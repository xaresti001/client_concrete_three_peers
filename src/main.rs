use concrete_lib::*;
use std::thread;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write};
use std::io::{BufRead, BufReader};
use std::time;
use serde::{Serialize, Deserialize};
use rand::*;
use core::ptr::null;
use itertools::Itertools;
use ndarray::Array;
use std::time::Duration;
use std::fs::OpenOptions;
use std::io::LineWriter;
use chrono;
use chrono::{DateTime, Utc};
use rand::distributions::uniform::SampleBorrow;
use std::convert::TryInto;

// Message-code struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteMessageCode {
    code : i32
}

// Ciphertext message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteCiphertext {
    message : VectorLWE
}

// Secret Key message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteSecretKey {
    secret_key : LWESecretKey
}

// Key Switching message struct
#[derive(Serialize, Deserialize, Debug)]
struct ConcreteKSK {
    change_key : LWEKSK
}

// Operation request
#[derive(Serialize, Deserialize, Debug)]
struct OperationRequest {
    sensor_ip : String,
    ciphertext_amount : i32
}

// Operation response
#[derive(Serialize, Deserialize, Debug)]
struct OperationResponse {
    ciphertexts : Vec<OperationIndividualResponse>
}

// Operation response
#[derive(Serialize, Deserialize, Debug)]
struct OperationIndividualResponse {
    ciphertext : VectorLWE,
    initial_datetime : String,
    final_datetime : String
}

fn secret_key_request_connection(sensor_ip_address : String){
    let peer_complete_address = format!("{}{}", sensor_ip_address, ":4444");
    // Connect to Sensor - Regular TCP connection
    match TcpStream::connect(peer_complete_address) {
        Ok(stream) => {
            println!("Successfully connected to server!");
            send_secret_key_request(&stream);
            receive_and_save_secret_key(&stream);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Sending thread terminated.");
}

fn operation_request_connection(sensor_ip_address : String, amount : i32){
    // Connect to server - Regular TCP connection
    match TcpStream::connect("127.0.0.1:3333") {
        Ok(stream) => {
            println!("Successfully connected to server!");
            send_operation_request(&stream, sensor_ip_address, amount);
            receive_operation_response(&stream);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Sending thread terminated.");
}

fn receive_operation_response(stream : &TcpStream) -> OperationResponse{
    // RECEIVING MODULE
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();

    // _______________ // DUMMY READ - WILL RECEIVE CODE 2
    buffer.clear();
    let read_bytes = reader.read_until(b'\n', &mut buffer).unwrap();

    if read_bytes == 0 { // If there is no incoming data
        return ();
    }
    // _______________ // END OF DUMMY READ

    buffer.clear();
    let read_bytes = reader.read_until(b'\n', &mut buffer).unwrap();

    if read_bytes == 0 { // If there is no incoming data
        return ();
    }

    // Deserialize
    let operation_response : OperationResponse = serde_json::from_slice(&buffer).unwrap();
    return operation_response;
}

fn send_secret_key_request(mut stream : &TcpStream){
    // Prepare and send Message Code
    let msg_code = ConcreteMessageCode {
        code : 3 // Code for Secret Key Request
    };
    stream.write(serde_json::to_string(&msg_code).unwrap().as_bytes()).unwrap();
    stream.write(b"\n").unwrap(); // Necessary in order to Stop reading or receiving data from
}

fn send_operation_request(mut stream : &TcpStream, sensor_ip : String, amount : i32){
    // Prepare and send Message Code
    let msg_code = ConcreteMessageCode {
        code : 1 // Code for Operation Request
    };
    stream.write(serde_json::to_string(&msg_code).unwrap().as_bytes()).unwrap();
    stream.write(b"\n").unwrap(); // Necessary in order to Stop reading or receiving data from

    // Prepare and send Operation Request
    let request = OperationRequest{
        sensor_ip,
        ciphertext_amount : amount
    };
    stream.write(serde_json::to_string(&request).unwrap().as_bytes()).unwrap();
    stream.write(b"\n").unwrap(); // Necessary in order to Stop reading or receiving data from
}

fn receive_and_save_secret_key(stream : &TcpStream){
    // RECEIVING MODULE
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();

    // _______________ // DUMMY READ - WILL RECEIVE CODE 4
    buffer.clear();
    let read_bytes = reader.read_until(b'\n', &mut buffer).unwrap();

    if read_bytes == 0 { // If there is no incoming data
        return ();
    }
    // _______________ // END OF DUMMY READ

    buffer.clear();
    let read_bytes = reader.read_until(b'\n', &mut buffer).unwrap();

    if read_bytes == 0 { // If there is no incoming data
        return ();
    }

    // Deserialize
    let secret_key : LWESecretKey = serde_json::from_slice(&buffer).unwrap();
    save_sensor_secret_key(stream, secret_key);
}

fn save_sensor_secret_key(stream : &TcpStream, secret_key : LWESecretKey){
    // Get peer's IP address
    let peer_ip_owned : String = stream.peer_addr().unwrap().ip().to_string().to_owned();
    let filename = format!("{}{}", peer_ip_owned, "_secret_key.json");
    secret_key.save(&filename);
}

// Client device will ask for sensor's IP address and the amount of measurements to calculate mean value.
// Then, the device will ask the server for information. Will receive a Struct with a response-vector in it.
// In order to decrypt the information, the original sensor needs to make the first decryption to the ciphertexts.
fn main() {
    let mut sensor_ip_address = String::new();
    let mut amount_str = String::new();
    let mut amount : i32;

    println!("Enter sensor's IP Address: ");
    std::io::stdin().read_line(&mut sensor_ip_address).unwrap();
    println!("Enter amount of measurements to calculate mean value: ");
    std::io::stdin().read_line(&mut amount_str).unwrap();
    amount = amount_str.parse().unwrap();

    // secret_key_request_connection();
    // operation_request_connection();
    // verification_connection();
    // display_information();
}
