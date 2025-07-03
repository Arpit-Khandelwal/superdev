use core::str;
use std::str::FromStr;

use actix_web::error::JsonPayloadError;
use actix_web::web::Json;
// write a simple endpoint to return a greeting message using actix-web
use actix_web::{App, HttpResponse, HttpServer, Responder, Result, web};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::error;
use solana_sdk::instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::signer::keypair;
use spl_token::id as spl_token;
use spl_token::instruction as token_instruction;
async fn greet() -> impl Responder {
    println!("Received a request to greet");
    "Hello, world!"
}
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret_key: String,
}

async fn keypair() -> impl Responder {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey();
    let secret_key = keypair.to_base58_string();

    // response:
    //     {
    //   "success": true,
    //   "data": {
    //     "pubkey": "base58-encoded-public-key",
    //     "secret": "base58-encoded-secret-key"
    //   }
    // }

    let response = serde_json::json!({
        "success": true,
        "data": {
            "pubkey": pubkey.to_string(),
            "secret": secret_key,
        }
    });
    web::Json(response)
}

#[derive(Deserialize)]
struct CreateTokenMintRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}
// Create a new SPL token initialise mint instruction.
async fn create_spl_token_mint(req: Result<web::Json<CreateTokenMintRequest>>) -> impl Responder {
    // this takes a request:
    //{
    //   "mintAuthority": "base58-encoded-public-key",
    //   "mint": "base58-encoded-public-key"
    //   "decimals": 6
    // }

    match req {
        Ok(req) => {
            // test if request is valid with fields mintAuthority, mint, and decimals
            if req.mintAuthority.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `mintAuthority` is required."
                }));
            }
            if req.mint.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `mint` is required."
                }));
            }
            if req.decimals > 9 {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `decimals` must be between 0 and 9."
                }));
            }

            let mint_authority = match Pubkey::from_str(&req.mintAuthority) {
                Ok(pubkey) => pubkey,
                Err(_) => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "success": false,
                        "error": "Invalid `mintAuthority` public key."
                    }));
                }
            };

            let mint = match Pubkey::from_str(&req.mint) {
                Ok(pubkey) => pubkey,
                Err(_) => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "success": false,
                        "error": "Invalid `mint` public key."
                    }));
                }
            };

            let decimals = match req.decimals {
                0..=9 => req.decimals,
                _ => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "success": false,
                        "error": "Invalid `decimals`. Must be between 0 and 9."
                    }));
                }
            };

            let instruction = match token_instruction::initialize_mint(
                &spl_token::ID,
                &mint,
                &mint_authority,
                None,
                decimals,
            ) {
                Ok(ix) => ix,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "success": false,
                        "error": format!("Failed to create initialize mint instruction: {}", e)
                    }));
                }
            };

            // println!("Created instruction: {:?}", instruction);

            //{
            //   "success": true,
            //   "data": {
            //     "program_id": "string",
            //     "accounts": [{
            // 	    pubkey: "pubkey",
            // 	    is_signer: boolean,
            // 	    is_writable: boolean
            //     }]...,
            //     "instruction_data": "base64-encoded-data"
            //   }
            // }

            let response = serde_json::json!({
                "success": true,
                "data": {
                    "program_id": instruction.program_id.to_string(),
                    "accounts": instruction
                        .accounts
                        .iter()
                        .map(|account| {
                            serde_json::json!({
                                "pubkey": account.pubkey.to_string(),
                                "is_signer": account.is_signer,
                                "is_writable": account.is_writable,
                            })
                        })
                        .collect::<Vec<_>>(),
                    "instruction_data": instruction.data,
                }
            });

            //return HTTP 200
            HttpResponse::Ok().json(response)
        }
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid request format."
            }));
        }
    }
}

#[derive(Deserialize)]
struct MintTokenInstructionRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token_instruction(
    req: Result<web::Json<MintTokenInstructionRequest>>,
) -> impl Responder {
    //create a mint-to instruction for an SPL token
    match req {
        Ok(req) => {
            // Validate the request fields
            if req.mint.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `mint` is required."
                }));
            }
            if req.destination.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `destination` is required."
                }));
            }
            if req.authority.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `authority` is required."
                }));
            }
            if req.amount == 0 {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `amount` must be greater than 0."
                }));
            }

            let mint = match Pubkey::from_str(&req.mint) {
                Ok(pubkey) => pubkey,
                Err(_) => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "success": false,
                        "error": "Invalid `mint` public key."
                    }));
                }
            };
            let destination = match Pubkey::from_str(&req.destination) {
                Ok(pubkey) => pubkey,
                Err(_) => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "success": false,
                        "error": "Invalid `destination` public key."
                    }));
                }
            };
            let authority = match Pubkey::from_str(&req.authority) {
                Ok(pubkey) => pubkey,
                Err(_) => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "success": false,
                        "error": "Invalid `authority` public key."
                    }));
                }
            };

            // Create the mint-to instruction
            let instruction = match token_instruction::mint_to(
                &spl_token::ID,
                &mint,
                &destination,
                &authority,
                &[],
                req.amount,
            ) {
                Ok(ix) => ix,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "success": false,
                        "error": format!("Failed to create mint-to instruction: {}", e)
                    }));
                }
            };
            // Construct the response
            let response = serde_json::json!({
            "success": true,
            "data": {
                "program_id": instruction.program_id.to_string(),
                "accounts": instruction
                    .accounts
                    .iter()
                    .map(|account| {
                        serde_json::json!({
                            "pubkey": account.pubkey.to_string(),
                            "is_signer": account.is_signer,
                            "is_writable": account.is_writable,
                        })
                    })
                    .collect::<Vec<_>>(),
                "instruction_data": general_purpose::STANDARD.encode(instruction.data),
            }});
            // Return HTTP 200 with the response
            HttpResponse::Ok().json(response)
        }
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid request format."
            }));
        }
    }
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

fn keypair_from_base58_string(secret: &str) -> Result<Keypair, String> {
    let bytes = bs58::decode(secret)
        .into_vec()
        .map_err(|_| "Invalid base58 in `secret`")?;
    if bytes.len() != 64 {
        return Err("Secret key must be 64 bytes".to_string());
    }
    Keypair::from_bytes(&bytes).map_err(|_| "Invalid keypair bytes".to_string())
}

async fn sign_message(req: Result<web::Json<SignMessageRequest>>) -> impl Responder {
    match req {
        Ok(req) => {
            // Validate the request fields
            if req.message.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `message` is required."
                }));
            }
            if req.secret.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Invalid request. `secret` is required."
                }));
            }

            let keypair = match keypair_from_base58_string(&req.secret) {
                Ok(kp) => kp,
                Err(e) => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "success": false,
                        "error": e
                    }));
                }
            };

            // Decode the secret key from base58
            // check if the secret key is a valid base58 string

            // Sign the message
            let message_bytes = req.message.as_bytes();
            let signature = keypair.sign_message(message_bytes);
            let public_key = keypair.pubkey();

            // Verify the signature
            if !signature.verify(public_key.as_ref(), message_bytes) {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Failed to verify signature."
                }));
            }

            if !public_key.is_on_curve() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "error": "Failed to verify public key."
                }));
            }

            // Construct the response
            let response = serde_json::json!({
                "success": true,
                "data": {
                    "signature": general_purpose::STANDARD.encode(signature.to_string()),
                    "public_key": public_key,
                    "message": req.message
                }
            });

            // Return HTTP 200 with the response
            return HttpResponse::Ok().json(response);
        }
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid request format."
            }));
        }
    }
}

#[actix_web::main]
async fn main() {
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(greet))
            .route("/greet", web::get().to(greet))
            .route("/keypair", web::post().to(keypair))
            .route("/token/create", web::post().to(create_spl_token_mint))
            .route("/token/mint", web::post().to(mint_token_instruction))
            .route("/message/sign", web::post().to(sign_message))
    })
    .bind("127.0.0.1:8080")
    .expect("Failed to bind server")
    .run()
    .await
    .expect("Failed to run server");
}
