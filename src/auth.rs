use serde::{Deserialize, Serialize};

use dotenv::dotenv;
use std::{env, fs, error::Error};
use reqwest::Client;

#[derive(Debug, Serialize)]
struct SignUpPayload {
    email: String,
    password: String,
    returnSecureToken: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub idToken: String,
    pub localId: String,
    pub email: String,
    pub refreshToken: String,
}

#[derive(Deserialize)]
struct FirebaseResponseRaw {
    idToken: String,
    localId: String,
    refreshToken: String,
}

#[derive(Debug, Deserialize)]
pub struct FirebaseError {
    error: FirebaseErrorDetails,
}

#[derive(Debug, Deserialize)]
pub struct FirebaseErrorDetails {
    message: String,
}

/// Signs up a new user and saves token
pub async fn sign_up(email: &str, password: &str) -> Result<AuthResponse, String> {
    dotenv().ok();
    let api_key = env::var("FIREBASE_API_KEY").expect("Missing FIREBASE_API_KEY");
    let url = format!("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={}", api_key);

    let payload = SignUpPayload {
        email: email.to_string(),
        password: password.to_string(),
        returnSecureToken: true,
    };

    let client = Client::new();
    let res = client.post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status().is_success() {
        let auth = res.json::<AuthResponse>().await.map_err(|e| e.to_string())?;
        save_auth_token(&auth)?;
        Ok(auth)
    } else {
        let err = res.json::<FirebaseError>().await.unwrap();
        Err(err.error.message)
    }
}

/// Logs in an existing user and saves the token
pub async fn login(email: &str, password: &str) -> Result<AuthResponse, String> {
    dotenv().ok();
    let api_key = env::var("FIREBASE_API_KEY").expect("Missing FIREBASE_API_KEY");
    let url = format!("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={}", api_key);

    let payload = SignUpPayload {
        email: email.to_string(),
        password: password.to_string(),
        returnSecureToken: true,
    };

    let client = Client::new();
    let res = client.post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if res.status().is_success() {
        let auth = res.json::<AuthResponse>().await.map_err(|e| e.to_string())?;
        save_auth_token(&auth)?;
        Ok(auth)
    } else {
        let err = res.json::<FirebaseError>().await.unwrap();
        Err(err.error.message)
    }
}

/// Saves auth token and UID to a local JSON file
fn save_auth_token(auth: &AuthResponse) -> Result<(), String> {
    fs::write(
        "auth_token.json",
        serde_json::to_string_pretty(auth).map_err(|e| e.to_string())?
    ).map_err(|e| e.to_string())?;

    Ok(())
}

/// Loads the token annd UID when needed
pub fn load_auth_token() -> Result<AuthResponse, Box<dyn Error>> {
    let data = fs::read_to_string("auth_token.json")?;
    let auth: AuthResponse = serde_json::from_str(&data)?;
    Ok(auth)
}
