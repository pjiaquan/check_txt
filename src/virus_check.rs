use anyhow::Result;
use reqwest::Client;
use serde::{ Deserialize, Serialize };
use sha2::{ Sha256, Digest };
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
struct VirusTotalResponse {
    data: VirusTotalData,
}

#[derive(Debug, Serialize, Deserialize)]
struct VirusTotalData {
    attributes: VirusTotalAttributes,
}

#[derive(Debug, Serialize, Deserialize)]
struct VirusTotalAttributes {
    last_analysis_stats: LastAnalysisStats,
    last_analysis_results: std::collections::HashMap<String, AnalysisResult>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LastAnalysisStats {
    malicious: i32,
    suspicious: i32,
    undetected: i32,
    timeout: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnalysisResult {
    category: String,
    result: Option<String>,
}

pub struct VirusChecker {
    client: Client,
    api_key: String,
}

impl VirusChecker {
    pub fn new() -> Result<Self> {
        dotenv::dotenv().ok();
        let api_key = env
            ::var("VIRUSTOTAL_API_KEY")
            .map_err(|_| anyhow::anyhow!("VIRUSTOTAL_API_KEY not found in environment variables"))?;

        Ok(VirusChecker {
            client: Client::new(),
            api_key,
        })
    }

    pub async fn check_file(&self, path: &PathBuf) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        // Calculate file hash
        let file_hash = self.calculate_file_hash(path)?;

        // Check VirusTotal
        if let Ok(vt_issues) = self.check_virustotal(&file_hash).await {
            issues.extend(vt_issues);
        }

        Ok(issues)
    }

    fn calculate_file_hash(&self, path: &PathBuf) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    async fn check_virustotal(&self, file_hash: &str) -> Result<Vec<String>> {
        let url = format!("https://www.virustotal.com/api/v3/files/{}", file_hash);

        let response = self.client.get(&url).header("x-apikey", &self.api_key).send().await?;

        if !response.status().is_success() {
            return Ok(vec![]);
        }

        let vt_response: VirusTotalResponse = response.json().await?;
        let mut issues = Vec::new();

        let stats = &vt_response.data.attributes.last_analysis_stats;
        if stats.malicious > 0 {
            issues.push(
                format!("File detected as malicious by {} antivirus engines", stats.malicious)
            );
        }
        if stats.suspicious > 0 {
            issues.push(
                format!("File detected as suspicious by {} antivirus engines", stats.suspicious)
            );
        }

        // Add specific detection details
        for (engine, result) in &vt_response.data.attributes.last_analysis_results {
            if result.category == "malicious" || result.category == "suspicious" {
                if let Some(detection) = &result.result {
                    issues.push(format!("Detected by {}: {}", engine, detection));
                }
            }
        }

        Ok(issues)
    }
}
