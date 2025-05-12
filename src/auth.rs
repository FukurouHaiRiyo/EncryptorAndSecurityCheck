use serde::{Deserialize, Serialize};

use dotenv::dotenv;
use std::env;
use reqwest::Client;

#[derive(Debug, Serialize)]
struct SignUpPayload {
    email: String,
    password: String,
    returnSecureToken: bool,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub idToken: String,
    pub localId: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct FirebaseError {
    error: FirebaseErrorDetails,
}

#[derive(Debug, Deserialize)]
pub struct FirebaseErrorDetails {
    message: String,
}

/// Signs up a new user
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
        Ok(res.json::<AuthResponse>().await.unwrap())
    } else {
        let err = res.json::<FirebaseError>().await.unwrap();
        Err(err.error.message)
    }
}

/// Logs in an existing user
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
        Ok(res.json::<AuthResponse>().await.unwrap())
    } else {
        let err = res.json::<FirebaseError>().await.unwrap();
        Err(err.error.message)
    }
}
