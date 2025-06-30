use actix_web::{App, HttpResponse, HttpServer, Responder, web, middleware::Logger};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_associated_token_account;
use spl_token::{
    instruction::{initialize_mint, mint_to, transfer},
};
use std::str::FromStr;
use serde_json;

#[derive(Serialize)]
struct KeypairResponse {
    success: bool,
    data: KeypairData,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}



#[actix_web::post("/keypair")]
async fn generate_keypair() -> impl Responder {
    let keypair = Keypair::new();

    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    let response = KeypairResponse {
        success: true,
        data: KeypairData { pubkey, secret },
    };

    HttpResponse::Ok().json(response)
}

#[derive(Deserialize, Serialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    success: bool,
    data: TokenInstructionData,
}

#[derive(Serialize)]
struct TokenInstructionData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Deserialize, Serialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct MintTokenResponse {
    success: bool,
    data: TokenInstructionData,
}

#[derive(Deserialize, Serialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: SignMessageData,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize, Serialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    data: VerifyMessageData,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize, Serialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    success: bool,
    data: SolInstructionData,
}

#[derive(Serialize)]
struct SolInstructionData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize, Serialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    data: TokenTransferInstructionData,
}

#[derive(Serialize)]
struct TokenTransferInstructionData {
    program_id: String,
    accounts: Vec<TokenTransferAccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenTransferAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

fn main() {
    if let Err(e) = actix_web::rt::System::new().block_on(run_server()) {
        eprintln!("Failed to start server: {}", e);
        std::process::exit(1);
    }
}

async fn run_server() -> std::io::Result<()> {
    let port = 8080;
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(generate_keypair)
            .service(create_token)
            .service(mint_token)
            .service(sign_message)
            .service(verify_message)
            .service(send_sol)
            .service(send_token)
    })
    .bind(("127.0.0.1", port))?
    .workers(8)
    .run()
    .await
}

#[actix_web::post("/token/create")]
async fn create_token(req: web::Json<CreateTokenRequest>) -> impl Responder {
    if req.mint_authority.is_empty() || req.mint.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint authority public key"
            }));
        }
    };

    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            }));
        }
    };

    let instruction = initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority,
        None,
        req.decimals,
    )
    .unwrap();

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| AccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = base64::prelude::BASE64_STANDARD.encode(&instruction.data);

    let response = CreateTokenResponse {
        success: true,
        data: TokenInstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    HttpResponse::Ok().json(response)
}

#[actix_web::post("/token/mint")]
async fn mint_token(req: web::Json<MintTokenRequest>) -> impl Responder {
    if req.mint.is_empty() || req.destination.is_empty() || req.authority.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    if req.amount == 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        }));
    }

    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint public key"
            }));
        }
    };

    let destination_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid destination public key"
            }));
        }
    };

    let authority_pubkey = match Pubkey::from_str(&req.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid authority public key"
            }));
        }
    };

    let instruction = mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[],
        req.amount,
    )
    .unwrap();

    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| AccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = base64::prelude::BASE64_STANDARD.encode(&instruction.data);

    let response = MintTokenResponse {
        success: true,
        data: TokenInstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    HttpResponse::Ok().json(response)
}

#[actix_web::post("/message/sign")]
async fn sign_message(req: web::Json<SignMessageRequest>) -> impl Responder {
    if req.message.is_empty() || req.secret.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    let secret_key = match bs58::decode(&req.secret).into_vec() {
        Ok(key) => key,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid secret key"
            }));
        }
    };

    let keypair = match Keypair::try_from(&secret_key[..]) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid secret key format"
            }));
        }
    };

    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let signature_base64 = BASE64_STANDARD.encode(signature.as_ref());

    let response = SignMessageResponse {
        success: true,
        data: SignMessageData {
            signature: signature_base64,
            public_key: keypair.pubkey().to_string(),
            message: req.message.clone(),
        },
    };

    HttpResponse::Ok().json(response)
}

#[actix_web::post("/message/verify")]
async fn verify_message(req: web::Json<VerifyMessageRequest>) -> impl Responder {
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(key) => key,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid public key"
            }));
        }
    };

    let signature_bytes = match BASE64_STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid signature format"
            }));
        }
    };

    let signature = match Signature::try_from(&signature_bytes[..]) {
        Ok(sig) => sig,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid signature"
            }));
        }
    };

    let message_bytes = req.message.as_bytes();
    let is_valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    let response = VerifyMessageResponse {
        success: true,
        data: VerifyMessageData {
            valid: is_valid,
            message: req.message.clone(),
            pubkey: req.pubkey.clone(),
        },
    };

    HttpResponse::Ok().json(response)
}

#[actix_web::post("/send/sol")]
async fn send_sol(req: web::Json<SendSolRequest>) -> impl Responder {
    if req.from.is_empty() || req.to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    if req.lamports == 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Transfer amount must be greater than 0"
        }));
    }

    let from_pubkey = match Pubkey::from_str(&req.from) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid from address"
            }));
        }
    };

    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid to address"
            }));
        }
    };

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    let accounts: Vec<String> = instruction
        .accounts
        .iter()
        .map(|account| account.pubkey.to_string())
        .collect();

    let instruction_data = BASE64_STANDARD.encode(&instruction.data);

    let response = SendSolResponse {
        success: true,
        data: SolInstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    HttpResponse::Ok().json(response)
}

#[actix_web::post("/send/token")]
async fn send_token(req: web::Json<SendTokenRequest>) -> impl Responder {
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }

    if req.amount == 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Transfer amount must be greater than 0"
        }));
    }

    let destination_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid destination address"
            }));
        }
    };

    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid mint address"
            }));
        }
    };

    let owner_pubkey = match Pubkey::from_str(&req.owner) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "Invalid owner address"
            }));
        }
    };

    let source_pubkey =
        spl_associated_token_account::get_associated_token_address(&owner_pubkey, &mint_pubkey);

    let instruction = transfer(
        &spl_token::id(),
        &source_pubkey,
        &destination_pubkey,
        &owner_pubkey,
        &[],
        req.amount,
    )
    .unwrap();

    let accounts: Vec<TokenTransferAccountInfo> = instruction
        .accounts
        .iter()
        .map(|account| TokenTransferAccountInfo {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
        })
        .collect();

    let instruction_data = BASE64_STANDARD.encode(&instruction.data);

    let response = SendTokenResponse {
        success: true,
        data: TokenTransferInstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    HttpResponse::Ok().json(response)
}
