use reqwest::{Client, multipart};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::error::Error;
use tokio::fs::File as TokioFile;
use tokio::io::AsyncWriteExt;

use dotenv::dotenv;
use std::{env, fs};

pub async fn upload_to_firebase(
    file_path: &str,
    firebase_token: &str,
    user_id: &str,
) -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    let project_id = env::var("PROJECT_ID").expect("Missing PROJECT_ID");

    let file_name = Paht::new(file_path)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let timestamp = chrono::Utc::now().timestamp();
    let storage_path = format!("encrypted/{}/{}_{}", user_id, timestamp, file_name);

    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let part = multipart::Part::bytes(buffer).file_name(file_name.clone()).mime_str("application/octet-stream")?;
    let form = multipart::Form::new().part("file", part);

    let client = reqwest::Client::new();
    let url = format!(
        "https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o?name={}",
        urlencoding::encode(&storage_path)
    );

    let res = client
            .post(&url)
            .bearer_auth(firebase_token)
            .multipart(form)
            .send()
            .await?;

    if res.status().is_success() {
        println!("✅ Upload successful to: {}", storage_path);
        Ok(())
    } else {
        Err(Box::from(format!("❌ Upload failed: {}", res.text().await?)))
    }
}

pub async fn download_from_firebase(
    file_name: &str,
    output_path: &str,
    firebase_token: &str,
) -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    let project_id = env::var("PROJECT_ID").expect("Missing PROJECT_ID");

    let url = format!(
        "https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o/{}?alt=media",
        encode(file_name)
    );

    let client = Client::new();
    let res = client
        .get(&url)
        .bearer_auth(firebase_token)
        .send()
        .await?;

    if !res.status().is_success() {
        return Err(Box::from(format!("❌ Download failed: {:?}", res.text().await?)));
    }

    let bytes = res.bytes().await?;
    let mut file = TokioFile::create(output_path).await?;
    file.write_all(&bytes).await?;

    println!("✅ Download successful to: {}", output_path);
    Ok(())
}
