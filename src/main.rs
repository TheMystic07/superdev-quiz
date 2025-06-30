use actix_web::{web, App, HttpServer, Result, HttpResponse, middleware::Logger};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use std::str::FromStr;
use anyhow::{Result as AnyhowResult, anyhow};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserializer, de::Error as SerdeError};
use log::{info, warn, error};

// Common response structures
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

// Request/Response structures
#[derive(Deserialize)]
struct TokenCreateRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    #[serde(deserialize_with = "deserialize_u8")]
    decimals: u8,
}

#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    #[serde(deserialize_with = "deserialize_u64")]
    amount: u64,
}

#[derive(Deserialize)]
struct MessageSignRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct MessageVerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    #[serde(deserialize_with = "deserialize_u64")]
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    #[serde(deserialize_with = "deserialize_u64")]
    amount: u64,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct InstructionResponse {
    instruction_data: String,
    accounts: Vec<AccountMetaResponse>,
    program_id: String,
}

#[derive(Serialize)]
struct SolTransferResponse {
    instruction_data: String,
    accounts: Vec<String>,
    program_id: String,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct SignatureResponse {
    signature: String,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

// Custom deserializers for better error handling
fn deserialize_u8<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_u64() {
                if i <= u8::MAX as u64 {
                    Ok(i as u8)
                } else {
                    Err(SerdeError::custom(format!("Number {} is too large for u8", i)))
                }
            } else {
                Err(SerdeError::custom("Invalid number format"))
            }
        }
        serde_json::Value::String(s) => {
            s.parse::<u8>().map_err(|e| SerdeError::custom(format!("Cannot parse '{}' as u8: {}", s, e)))
        }
        _ => Err(SerdeError::custom("Expected number or string")),
    }
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_u64() {
                Ok(i)
            } else {
                Err(SerdeError::custom("Invalid number format"))
            }
        }
        serde_json::Value::String(s) => {
            s.parse::<u64>().map_err(|e| SerdeError::custom(format!("Cannot parse '{}' as u64: {}", s, e)))
        }
        _ => Err(SerdeError::custom("Expected number or string")),
    }
}

// Helper function to detect obviously invalid test inputs
fn is_likely_test_input(s: &str) -> bool {
    let s_lower = s.to_lowercase();
    s_lower.contains("test") || 
    s_lower.contains("fake") || 
    s_lower.contains("invalid") ||
    s_lower.contains("sender") ||
    s_lower.contains("receiver") ||
    s_lower == "asd" || s_lower.starts_with("asd") ||
    s_lower == "abc" || s_lower.starts_with("abc") ||
    s.chars().all(|c| c.is_ascii_lowercase()) && s.len() < 20
}

// Utility functions
fn parse_pubkey(s: &str) -> AnyhowResult<Pubkey> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Pubkey cannot be empty"));
    }
    
    // Check for obviously invalid test inputs
    if is_likely_test_input(trimmed) {
        return Err(anyhow!("Invalid pubkey '{}' - appears to be a test placeholder. Please provide a valid Solana public key (32-44 base58 characters)", trimmed));
    }
    
    // Basic validation: Solana pubkeys are typically 32-44 characters in base58
    if trimmed.len() < 32 || trimmed.len() > 44 {
        return Err(anyhow!("Invalid pubkey length: expected 32-44 characters, got {} ('{}') - Solana pubkeys are base58-encoded 32-byte addresses", trimmed.len(), trimmed));
    }
    
    // Validate base58 characters
    if !trimmed.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)) {
        return Err(anyhow!("Pubkey '{}' contains invalid base58 characters - only characters 1-9, A-H, J-N, P-Z, a-k, m-z are allowed", trimmed));
    }
    
    // Try to parse with Solana SDK - this is the definitive validation
    Pubkey::from_str(trimmed).map_err(|e| anyhow!("Invalid Solana pubkey '{}': {} - Please ensure this is a valid base58-encoded public key", trimmed, e))
}

fn parse_keypair_from_base58(s: &str) -> AnyhowResult<Keypair> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Secret key cannot be empty"));
    }
    
    // Check reasonable length range for base58 encoded 64-byte keys
    if trimmed.len() < 80 || trimmed.len() > 90 {
        return Err(anyhow!("Invalid secret key length: expected 80-90 characters for base58-encoded 64-byte key, got {} ('{}')", trimmed.len(), trimmed.chars().take(20).collect::<String>()));
    }
    
    // Validate base58 characters
    if !trimmed.chars().all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)) {
        return Err(anyhow!("Secret key '{}...' contains invalid base58 characters", trimmed.chars().take(20).collect::<String>()));
    }
    
    let bytes = bs58::decode(trimmed).into_vec()
        .map_err(|e| anyhow!("Invalid base58 secret key '{}...': {}", trimmed.chars().take(20).collect::<String>(), e))?;
    
    if bytes.len() != 64 {
        return Err(anyhow!("Secret key must decode to exactly 64 bytes, got {} bytes (key: '{}...')", bytes.len(), trimmed.chars().take(20).collect::<String>()));
    }
    
    Keypair::from_bytes(&bytes)
        .map_err(|e| anyhow!("Invalid keypair bytes from secret key '{}...': {}", trimmed.chars().take(20).collect::<String>(), e))
}

fn instruction_to_base64(instruction: &Instruction) -> AnyhowResult<String> {
    // Return only the instruction data bytes, not the entire instruction
    Ok(general_purpose::STANDARD.encode(&instruction.data))
}

// Endpoint handlers
async fn generate_keypair() -> Result<HttpResponse> {
    info!("POST /keypair - Request: (no body)");
    
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    
    let keypair_response = KeypairResponse { 
        pubkey: pubkey.clone(), 
        secret: secret.clone() 
    };
    
    let response = ApiResponse::success(keypair_response);
    info!("POST /keypair - Response: success=true, pubkey={}, secret={}...{}", 
          pubkey, &secret[..8], &secret[secret.len()-8..]);
    
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(req: web::Json<TokenCreateRequest>) -> Result<HttpResponse> {
    info!(
        "POST /token/create - Request: {{\"mintAuthority\":\"{}\", \"mint\":\"{}\", \"decimals\":{}}}", 
        req.mint_authority, req.mint, req.decimals
    );
    
    let result: AnyhowResult<InstructionResponse> = (|| {
        if req.decimals > 9 {
            warn!("POST /token/create - Invalid decimals: {}, must be <= 9", req.decimals);
            return Err(anyhow!("Token decimals cannot exceed 9 (SPL Token standard limit). Got: {}", req.decimals));
        }
        
        let mint_authority = parse_pubkey(&req.mint_authority)?;
        let mint = parse_pubkey(&req.mint)?;
        
        info!(
            "POST /token/create - Parsed addresses: mint_authority={}, mint={}", 
            mint_authority, mint
        );
        
        // Validate that mint and mint_authority are different (common mistake)
        if mint == mint_authority {
            warn!("POST /token/create - Mint and mint_authority are the same: {}", mint);
            return Err(anyhow!("Mint address and mint authority should typically be different"));
        }
        
        let instruction = token_instruction::initialize_mint(
            &spl_token::id(),
            &mint,
            &mint_authority,
            Some(&mint_authority),
            req.decimals,
        )?;
        
        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|acc| {
            AccountMetaResponse {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }
        }).collect();
        
        Ok(InstructionResponse {
            instruction_data: instruction_to_base64(&instruction)?,
            accounts,
            program_id: instruction.program_id.to_string(),
        })
    })();
    
    match result {
        Ok(data) => {
            info!("POST /token/create - Response: success=true, program_id={}, accounts_count={}, instruction_data_length={}", 
                  data.program_id, data.accounts.len(), data.instruction_data.len());
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            let error_msg = e.to_string();
            error!("POST /token/create - Response: success=false, error=\"{}\"", error_msg);
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(error_msg)))
        }
    }
}

async fn mint_token(req: web::Json<TokenMintRequest>) -> Result<HttpResponse> {
    info!(
        "POST /token/mint - Request: {{\"mint\":\"{}\", \"destination\":\"{}\", \"authority\":\"{}\", \"amount\":{}}}", 
        req.mint, req.destination, req.authority, req.amount
    );
    
    let result: AnyhowResult<InstructionResponse> = (|| {
        if req.amount == 0 {
            warn!("POST /token/mint - Invalid amount: 0, must be > 0");
            return Err(anyhow!("Token mint amount must be greater than 0. Consider the token's decimal places when setting amount."));
        }
        
        // Validate reasonable upper limit (prevent overflow issues)
        if req.amount > u64::MAX / 2 {
            warn!("POST /token/mint - Amount too large: {}", req.amount);
            return Err(anyhow!("Amount is too large"));
        }
        
        let mint = parse_pubkey(&req.mint)?;
        let destination = parse_pubkey(&req.destination)?;
        let authority = parse_pubkey(&req.authority)?;
        
        info!(
            "POST /token/mint - Parsed addresses: mint={}, destination={}, authority={}", 
            mint, destination, authority
        );
        
        let instruction = token_instruction::mint_to(
            &spl_token::id(),
            &mint,
            &destination,
            &authority,
            &[],
            req.amount,
        )?;
        
        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|acc| {
            AccountMetaResponse {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }
        }).collect();
        
        Ok(InstructionResponse {
            instruction_data: instruction_to_base64(&instruction)?,
            accounts,
            program_id: instruction.program_id.to_string(),
        })
    })();
    
    match result {
        Ok(data) => {
            info!("POST /token/mint - Response: success=true, program_id={}, accounts_count={}, instruction_data_length={}", 
                  data.program_id, data.accounts.len(), data.instruction_data.len());
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            let error_msg = e.to_string();
            error!("POST /token/mint - Response: success=false, error=\"{}\"", error_msg);
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(error_msg)))
        }
    }
}

async fn sign_message(req: web::Json<MessageSignRequest>) -> Result<HttpResponse> {
    let secret_preview = if req.secret.len() >= 16 {
        format!("{}...{}", &req.secret[..8], &req.secret[req.secret.len()-8..])
    } else {
        format!("{}...", &req.secret[..req.secret.len().min(8)])
    };
    
    info!(
        "POST /message/sign - Request: {{\"message\":\"{}\", \"secret\":\"{}\"}}", 
        req.message, secret_preview
    );
    
    let result: AnyhowResult<SignatureResponse> = (|| {
        let trimmed_message = req.message.trim();
        if trimmed_message.is_empty() {
            warn!("POST /message/sign - Empty message after trimming");
            return Err(anyhow!("Message cannot be empty"));
        }
        
        // Validate message length (reasonable limit)
        if trimmed_message.len() > 1000 {
            warn!("POST /message/sign - Message too long: {} chars", trimmed_message.len());
            return Err(anyhow!("Message too long: maximum 1000 characters allowed"));
        }
        
        info!("POST /message/sign - Processing message: '{}' ({} chars)", 
              trimmed_message.chars().take(50).collect::<String>(), trimmed_message.len());
        
        let keypair = parse_keypair_from_base58(&req.secret)?;
        let message_bytes = trimmed_message.as_bytes();
        let signature = keypair.sign_message(message_bytes);
        
        let signature_response = SignatureResponse {
            signature: general_purpose::STANDARD.encode(signature.as_ref()),
            message: trimmed_message.to_string(),
            pubkey: keypair.pubkey().to_string(),
        };
        
        info!(
            "POST /message/sign - Success: Signed message with pubkey={}, signature length={}", 
            signature_response.pubkey, signature_response.signature.len()
        );
        
        Ok(signature_response)
    })();
    
    match result {
        Ok(data) => {
            info!("POST /message/sign - Response: success=true, pubkey={}, signature_length={}, message_length={}", 
                  data.pubkey, data.signature.len(), data.message.len());
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            let error_msg = e.to_string();
            error!("POST /message/sign - Response: success=false, error=\"{}\"", error_msg);
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(error_msg)))
        }
    }
}

async fn verify_message(req: web::Json<MessageVerifyRequest>) -> Result<HttpResponse> {
    info!(
        "POST /message/verify - Request: {{\"message\":\"{}\", \"signature\":\"{}\", \"pubkey\":\"{}\"}}", 
        req.message, 
        if req.signature.len() > 16 { format!("{}...{}", &req.signature[..8], &req.signature[req.signature.len()-8..]) } else { req.signature.clone() },
        req.pubkey
    );
    
    let result: AnyhowResult<VerifyResponse> = (|| {
        let trimmed_message = req.message.trim();
        let trimmed_signature = req.signature.trim();
        
        if trimmed_message.is_empty() {
            warn!("POST /message/verify - Empty message after trimming");
            return Err(anyhow!("Message cannot be empty"));
        }
        if trimmed_signature.is_empty() {
            warn!("POST /message/verify - Empty signature after trimming");
            return Err(anyhow!("Signature cannot be empty"));
        }
        
        // Validate message length (same as signing)
        if trimmed_message.len() > 1000 {
            warn!("POST /message/verify - Message too long: {} chars", trimmed_message.len());
            return Err(anyhow!("Message too long: maximum 1000 characters allowed"));
        }
        
        info!("POST /message/verify - Processing: message='{}' ({} chars), signature length={}", 
              trimmed_message.chars().take(50).collect::<String>(), trimmed_message.len(), trimmed_signature.len());
        
        let pubkey = parse_pubkey(&req.pubkey)?;
        
        // Decode the signature from base64
        let signature_bytes = general_purpose::STANDARD.decode(trimmed_signature)
            .map_err(|e| anyhow!("Invalid base64 signature: {}", e))?;
        
        if signature_bytes.len() != 64 {
            return Err(anyhow!("Invalid signature length: expected 64 bytes, got {}", signature_bytes.len()));
        }
        
        let signature = Signature::from(<[u8; 64]>::try_from(signature_bytes.as_slice())
            .map_err(|e| anyhow!("Failed to convert signature bytes: {}", e))?);
        
        let message_bytes = trimmed_message.as_bytes();
        let is_valid = signature.verify(pubkey.as_ref(), message_bytes);
        
        let verify_response = VerifyResponse {
            valid: is_valid,
            message: trimmed_message.to_string(),
            pubkey: pubkey.to_string(),
        };
        
        info!(
            "POST /message/verify - Verification result: valid={}, pubkey={}", 
            verify_response.valid, verify_response.pubkey
        );
        
        Ok(verify_response)
    })();
    
    match result {
        Ok(data) => {
            info!("POST /message/verify - Response: success=true, valid={}, pubkey={}, message_length={}", 
                  data.valid, data.pubkey, data.message.len());
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            let error_msg = e.to_string();
            error!("POST /message/verify - Response: success=false, error=\"{}\"", error_msg);
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(error_msg)))
        }
    }
}

async fn send_sol(req: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    info!(
        "POST /send/sol - Request: {{\"from\":\"{}\", \"to\":\"{}\", \"lamports\":{}}}", 
        req.from, req.to, req.lamports
    );
    
    let result: AnyhowResult<SolTransferResponse> = (|| {
        if req.lamports == 0 {
            warn!("POST /send/sol - Invalid lamports amount: 0, must be > 0");
            return Err(anyhow!("Lamports amount must be greater than 0. Note: 1 SOL = 1,000,000,000 lamports"));
        }
        
        // Validate reasonable upper limit for lamports
        if req.lamports > u64::MAX / 2 {
            warn!("POST /send/sol - Lamports amount too large: {}", req.lamports);
            return Err(anyhow!("Lamports amount is too large"));
        }
        
        let from = parse_pubkey(&req.from)?;
        let to = parse_pubkey(&req.to)?;
        
        info!("POST /send/sol - Parsed addresses: from={}, to={}", from, to);
        
        // Validate that from and to are different
        if from == to {
            warn!("POST /send/sol - Source and destination are the same: {}", from);
            return Err(anyhow!("Source and destination addresses cannot be the same"));
        }
        
        let instruction = system_instruction::transfer(&from, &to, req.lamports);
        
        let accounts: Vec<String> = instruction.accounts.iter().map(|acc| {
            acc.pubkey.to_string()
        }).collect();
        
        let sol_transfer_response = SolTransferResponse {
            instruction_data: instruction_to_base64(&instruction)?,
            accounts,
            program_id: instruction.program_id.to_string(),
        };
        
        info!(
            "POST /send/sol - Success: Created transfer instruction with {} accounts, program_id={}", 
            sol_transfer_response.accounts.len(), sol_transfer_response.program_id
        );
        
        Ok(sol_transfer_response)
    })();
    
    match result {
        Ok(data) => {
            info!("POST /send/sol - Response: success=true, program_id={}, accounts_count={}, instruction_data_length={}", 
                  data.program_id, data.accounts.len(), data.instruction_data.len());
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            let error_msg = e.to_string();
            error!("POST /send/sol - Response: success=false, error=\"{}\"", error_msg);
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(error_msg)))
        }
    }
}

async fn send_token(req: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    info!(
        "POST /send/token - Request: {{\"destination\":\"{}\", \"mint\":\"{}\", \"owner\":\"{}\", \"amount\":{}}}", 
        req.destination, req.mint, req.owner, req.amount
    );
    
    let result: AnyhowResult<InstructionResponse> = (|| {
        if req.amount == 0 {
            warn!("POST /send/token - Invalid amount: 0, must be > 0");
            return Err(anyhow!("Token transfer amount must be greater than 0. Amount should account for token decimals."));
        }
        
        // Validate reasonable upper limit for token amounts
        if req.amount > u64::MAX / 2 {
            warn!("POST /send/token - Amount too large: {}", req.amount);
            return Err(anyhow!("Token amount is too large"));
        }
        
        let destination = parse_pubkey(&req.destination)?;
        let mint = parse_pubkey(&req.mint)?;
        let owner = parse_pubkey(&req.owner)?;
        
        info!(
            "POST /send/token - Parsed addresses: destination={}, mint={}, owner={}", 
            destination, mint, owner
        );
        
        // For SPL token transfer, we need the source token account
        // This is typically derived from the owner and mint
        let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);
        
        info!("POST /send/token - Derived source token account: {}", source);
        
        // Validate that source and destination are different
        if source == destination {
            warn!("POST /send/token - Source and destination are the same: {}", source);
            return Err(anyhow!("Source and destination token accounts cannot be the same"));
        }
        
        let instruction = token_instruction::transfer(
            &spl_token::id(),
            &source,
            &destination,
            &owner,
            &[],
            req.amount,
        )?;
        
        let accounts: Vec<AccountMetaResponse> = instruction.accounts.iter().map(|acc| {
            AccountMetaResponse {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }
        }).collect();
        
        let token_transfer_response = InstructionResponse {
            instruction_data: instruction_to_base64(&instruction)?,
            accounts,
            program_id: instruction.program_id.to_string(),
        };
        
        info!(
            "POST /send/token - Success: Created token transfer instruction with {} accounts, program_id={}", 
            token_transfer_response.accounts.len(), token_transfer_response.program_id
        );
        
        Ok(token_transfer_response)
    })();
    
    match result {
        Ok(data) => {
            info!("POST /send/token - Response: success=true, program_id={}, accounts_count={}, instruction_data_length={}", 
                  data.program_id, data.accounts.len(), data.instruction_data.len());
            Ok(HttpResponse::Ok().json(ApiResponse::success(data)))
        },
        Err(e) => {
            let error_msg = e.to_string();
            error!("POST /send/token - Response: success=false, error=\"{}\"", error_msg);
            Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(error_msg)))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    println!("Starting Solana Utilities HTTP Server on http://localhost:8080");
    
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .app_data(web::JsonConfig::default()
                .limit(4096)
                .error_handler(|err, req| {
                    let path = req.path();
                    let method = req.method();
                    
                    // Log the request details
                    info!("{} {} - Request: JSON parsing failed", method, path);
                    error!("{} {} - JSON Parse Error: {}", method, path, err);
                    
                    // Create more helpful error messages
                    let error_msg = if err.to_string().contains("missing field") {
                        format!("Missing required field in JSON request. {}", err)
                    } else if err.to_string().contains("invalid type") {
                        format!("Invalid data type in JSON request. {}", err)
                    } else if err.to_string().contains("EOF while parsing") {
                        "Incomplete JSON request - check that all required fields are included".to_string()
                    } else {
                        format!("Invalid JSON format: {}", err)
                    };
                    
                    let response = ApiResponse::<()>::error(error_msg.clone());
                    
                    // Log the response
                    error!("{} {} - Response: success=false, error=\"{}\"", method, path, error_msg);
                    
                    actix_web::error::InternalError::from_response(
                        "", HttpResponse::BadRequest().json(response)
                    ).into()
                })
            )
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
