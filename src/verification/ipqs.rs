use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashMap;

/// Represents the response from IPQS API
#[derive(Debug, Deserialize)]
pub struct IPQSResponse {
    pub success: bool,
    pub valid: bool,
    pub recent_abuse: bool,
    pub fraud_score: Option<u8>,
}

/// Main struct for interacting with the IPQS API
pub struct IPQS {
    key: String,
}

impl IPQS {
    /// Creates a new instance of IPQS with the provided API key
    pub fn new (key: &str) -> Self {
        IPQS {
            key: key.to_string(),
        }
    }

    /// Queries the IPQS phone number validation API
    pub fn phone_number_api(&self, phone_number: &str, vars: &Vec<(&str, &str)>) -> Result<IPQSResponse, String> {
        let url = format!(
            "https://www.ipqualityscore.com/api/json/phone/{}/{}",
            self.key, phone_number
        );

        let client = Client::new();
        let mut params = HashMap::new();
        for (key, value) in vars {
            params.insert(*key, *value);
        }

        let response = client
            .get(&url)
            .query(&params)
            .send()
            .map_err(|e| e.to_string())?;

        let result = response.json::<IPQSResponse>().map_err(|e| e.to_string())?;
        println!("{:?}", result); // Debug print

        Ok(result)
    }
}
