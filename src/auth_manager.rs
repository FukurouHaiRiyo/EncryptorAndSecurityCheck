use firebase_auth::FirebaseAuth;
use firebase_rs::Firebase;
use serde::{Deserialize};
use std::error::Error;

const FIREBASE_DB_URL: &str = "";
const API_KEY: &str = "";

#[derive(Debug, Deserialize)]
struct UserRole{
    role: String,
}

/// Authenicate user and get their role
pub async fn authenticate_user(id_token: &str) -> Result<Option<String>, Box<dyn, Error>> {
    let auth = FirebaseAuth::new(API_KEY);

    // Verify the id token
    if let Some(claims) = auth.verify_id_token(id_token).await? {
        let uid = claims.sub;

        // Fetch user role from Firebase Realtime Database
        
    }
}
