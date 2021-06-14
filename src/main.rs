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
    ciphertext_amount : i32,
    sensor_ip : String
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
    println!("Connecting to: {:?}", peer_complete_address);
    // Connect to Sensor - Regular TCP connection
    match TcpStream::connect(peer_complete_address) {
        Ok(stream) => {
            println!("Successfully connected to sensor!");
            // Send Secret Key request to sensor
            send_secret_key_request(&stream);
            println!("Secret Key request sent to sensor! Waiting for response...");
            // Receive Secret Key from sensor
            receive_and_save_secret_key(&stream);
            println!("Secret Key received from sensor!");
            // Shutdown connection
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Sending thread terminated.");
}

fn operation_request_and_verification(sensor_ip_address : String, amount : i32){
    // Connect to server - Regular TCP connection
    println!("Connecting to server...");
    match TcpStream::connect("127.0.0.1:3333") {
        Ok(stream) => {
            println!("Successfully connected to server!");
            // Send operation request
            send_operation_request(&stream, sensor_ip_address.clone(), amount);
            println!("Operation request successfully sent to server! Waiting for response...");
            // Receive operation response
            let response = receive_operation_response(&stream);
            println!("Operation response received from server! Verification needed to decrypt data.");
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            // Randomize, verify and decrypt response
            println!("Starting verification process...");
            verify_and_decrypt_operation_response(sensor_ip_address.clone(), response);
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Sending thread terminated.");
}

fn verify_and_decrypt_operation_response(sensor_ip_address : String, mut response : OperationResponse){
    // Load sensor's Secret Key
    let secret_key = load_sensor_secret_key(sensor_ip_address.clone());
    // Connect to Sensor - Regular TCP connection
    let peer_complete_address = format!("{}{}", sensor_ip_address, ":4444");
    println!("Connecting to: {:?}", peer_complete_address);
    match TcpStream::connect(peer_complete_address) {
        Ok(stream) => {
            println!("Successfully connected to Sensor!");
            println!("Proceeding to random addition, verification and decrypting data...");
            println!("\n\n--- OPERATION RESULTS ---");

            for message in response.ciphertexts.iter_mut(){
                // Generate random homomorphic sum to ciphertext
                let random_vector = random_sum(&mut message.ciphertext);
                // Send randomized ciphertext to sensor
                send_ciphertext(&stream, message.ciphertext.clone(), 5);
                // Receive verified ciphertext from sensor
                let verified_ciphertext = receive_ciphertext(&stream);
                // Undo random addition and decrypt ciphertext
                let data = decrypt_verified_ciphertext(&secret_key, &verified_ciphertext, &random_vector);
                // Printing the results
                println!("\nFrom: {:?} -- To: {:?}", message.initial_datetime, message.final_datetime);
                println!("Data: {:?}", data);
            }


        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Sending thread terminated.");




    // Load sensor's Secret Key
    let sensor_secret_key = load_sensor_secret_key(sensor_ip_address);

}

fn decrypt_verified_ciphertext(secret_key : &LWESecretKey, verified_ciphertext : &VectorLWE, random_vector : &Vec<f64>) -> Vec<f64>{
    // Negate randomized vector
    let temp_array = Array::from_vec(random_vector.to_vec());
    let constant : f64 = -1.0;
    let result = temp_array * constant;
    let random_vector_final = result.to_vec();

    // Undo randomized changes to ciphertext -> Obtain valid ciphertext
    verified_ciphertext.add_constant_dynamic_encoder(&random_vector_final).unwrap();
    // Decrypt and decode ciphertext
    let decrypted = verified_ciphertext.decrypt_decode(&secret_key).unwrap();
    return decrypted;
}

fn receive_ciphertext(stream : &TcpStream) -> VectorLWE{
    // RECEIVING MODULE
    let mut de = serde_json::Deserializer::from_reader(stream);
    let msg_code : ConcreteMessageCode = ConcreteMessageCode::deserialize(&mut de).unwrap();

    // RECEIVING MODULE
    let mut de = serde_json::Deserializer::from_reader(stream);
    let ciphertext : ConcreteCiphertext = ConcreteCiphertext::deserialize(&mut de).unwrap();
    return ciphertext.message;
}

fn send_ciphertext(mut stream : &TcpStream, ciphertext : VectorLWE, code_in : i32){
    // Prepare and send Message Code
    let msg_code = ConcreteMessageCode {
        code : code_in
    };
    stream.write(&serde_json::to_vec(&msg_code).unwrap()).unwrap();

    // Prepare and send ciphertext
    let ciphertext_msg = ConcreteCiphertext {
        message : ciphertext
    };
    stream.write(&serde_json::to_vec(&ciphertext_msg).unwrap()).unwrap();
}

fn random_sum(ciphertext : &mut VectorLWE) -> Vec<f64>{
    // Random Addition - Not implemented yes in separate function
    let mut rng = rand::thread_rng();
    // Vector of size 5, with random values between -500 and 500
    let constants: Vec<f64> = (0..3).map(|_| rng.gen_range(-100., 800.)).collect();
    // Execute homomorphic addition
    ciphertext.add_constant_dynamic_encoder(&constants).unwrap();
    return constants;
}

fn receive_operation_response(stream : &TcpStream) -> OperationResponse{
    // RECEIVING MODULE - Dummy read - Will receive code 2
    let mut de = serde_json::Deserializer::from_reader(stream);
    let msg_code : ConcreteMessageCode = ConcreteMessageCode::deserialize(&mut de).unwrap();

    // RECEIVING MODULE
    let mut de = serde_json::Deserializer::from_reader(stream);
    let operation_response : OperationResponse = OperationResponse::deserialize(&mut de).unwrap();
    return operation_response;
}

fn send_secret_key_request(mut stream : &TcpStream){
    // Prepare and send Message Code
    let msg_code = ConcreteMessageCode {
        code : 3 // Code for Secret Key Request
    };
    stream.write(&serde_json::to_vec(&msg_code).unwrap()).unwrap();
}

fn send_operation_request(mut stream : &TcpStream, sensor_ip : String, amount : i32){
    // Prepare and send Message Code
    let msg_code = ConcreteMessageCode {
        code : 1 // Code for Operation Request
    };
    stream.write(&serde_json::to_vec(&msg_code).unwrap()).unwrap();

    // Prepare and send Operation Request
    let request = OperationRequest{
        sensor_ip,
        ciphertext_amount : amount
    };
    println!("{}{:?}", request.sensor_ip, request.ciphertext_amount);
    stream.write(&serde_json::to_vec(&request).unwrap()).unwrap();
}

fn receive_and_save_secret_key(stream : &TcpStream){
    // RECEIVING MODULE - Dummy read - Will receive code 4
    let mut de = serde_json::Deserializer::from_reader(stream);
    let msg_code : ConcreteMessageCode = ConcreteMessageCode::deserialize(&mut de).unwrap();

    // RECEIVING MODULE
    let mut de = serde_json::Deserializer::from_reader(stream);
    let secret_key : ConcreteSecretKey = ConcreteSecretKey::deserialize(&mut de).unwrap();
    save_sensor_secret_key(stream, secret_key.secret_key);
}

fn save_sensor_secret_key(stream : &TcpStream, secret_key : LWESecretKey){
    // Get peer's IP address - Sensor's IP address
    let peer_ip_owned : String = stream.peer_addr().unwrap().ip().to_string().to_owned();
    // Obtain filename
    let filename = format!("{}{}", peer_ip_owned, "_secret_key.json");
    // Save sensor's Secret Key
    secret_key.save(&filename);
}

fn load_sensor_secret_key(sensor_ip_address : String) -> LWESecretKey{
    let filename = format!("{}{}", sensor_ip_address, "_secret_key.json");
    let secret_key = LWESecretKey::load(&filename).unwrap();
    return secret_key;
}

// Client device will ask for sensor's IP address and the amount of measurements to calculate mean value.
// Then, the device will ask the server for information. Will receive a Struct with a response-vector in it.
// In order to decrypt the information, the original sensor needs to make the first decryption to the ciphertexts.
fn main() {
    let mut sensor_ip_address = String::new();
    let mut amount_str = String::new();
    let mut amount : i32;

    println!("Enter sensor's IP Address: ");
    std::io::stdin().read_line(&mut sensor_ip_address).unwrap(); // Read from keyboard
    sensor_ip_address.pop(); // Remove last \n from buffer
    println!("Enter amount of measurements to calculate mean value: ");
    std::io::stdin().read_line(&mut amount_str).unwrap(); // Read from keyboard
    amount_str.pop(); // Remove last \n from buffer
    amount = amount_str.trim().parse::<i32>().unwrap(); // Parse String into i32

    println!("Requesting Sensor's Private Key (SK2)...");
    // Ask for sensor's Secret Key
    // secret_key_request_connection(sensor_ip_address.clone());
    println!("Requesting operation to server...");
    // Initialize operation request and ciphertext verification
    operation_request_and_verification(sensor_ip_address.clone(), amount);
}
