mod virus_check;
mod web_server;

use anyhow::{ Result };
use clap::Parser;
use indicatif::ProgressBar;
use regex::Regex;
use std::fs::File;
use std::io::{ BufRead, BufReader, Read };
use std::path::PathBuf;
use walkdir::WalkDir;
use zip::ZipArchive;
use std::collections::HashSet;
use virus_check::VirusChecker;
use log::{ info, error, warn };

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the file or directory to check
    #[arg(short, long)]
    path: Option<PathBuf>,

    /// File type to check (txt, pdf, epub)
    #[arg(short, long)]
    file_type: Option<String>,

    /// Maximum file size in MB
    #[arg(short, long, default_value = "100")]
    max_size: u64,

    /// Enable deep scanning (more thorough but slower)
    #[arg(short, long)]
    deep_scan: bool,

    /// Enable virus scanning (requires VIRUSTOTAL_API_KEY)
    #[arg(short, long)]
    virus_scan: bool,

    /// Start web server
    #[arg(short, long)]
    web: bool,
}

struct SecurityCheck {
    suspicious_patterns: Vec<Regex>,
    ad_patterns: Vec<Regex>,
    malware_patterns: Vec<Regex>,
    script_patterns: Vec<Regex>,
    encryption_patterns: Vec<Regex>,
    max_file_size: u64,
    deep_scan: bool,
    virus_checker: Option<VirusChecker>,
}

impl SecurityCheck {
    fn new(max_file_size: u64, deep_scan: bool, virus_scan: bool) -> Result<Self> {
        info!("Creating new SecurityCheck instance");
        let virus_checker = if virus_scan {
            info!("Initializing virus checker");
            Some(VirusChecker::new()?)
        } else {
            None
        };

        Ok(SecurityCheck {
            suspicious_patterns: vec![
                Regex::new(r"(?i)(eval\s*\()").unwrap(),
                Regex::new(r"(?i)(exec\s*\()").unwrap(),
                Regex::new(r"(?i)(system\s*\()").unwrap(),
                Regex::new(r"(?i)(shell_exec\s*\()").unwrap(),
                Regex::new(r"(?i)(base64_decode\s*\()").unwrap(),
                Regex::new(r"(?i)(gzinflate\s*\()").unwrap(),
                Regex::new(r"(?i)(str_rot13\s*\()").unwrap()
            ],
            ad_patterns: vec![
                Regex::new(r"(?i)(click here)").unwrap(),
                Regex::new(r"(?i)(buy now)").unwrap(),
                Regex::new(r"(?i)(limited time offer)").unwrap(),
                Regex::new(r"(?i)(special promotion)").unwrap(),
                Regex::new(r"(?i)(act now)").unwrap(),
                Regex::new(r"(?i)(call now)").unwrap(),
                Regex::new(r"(?i)(click below)").unwrap()
            ],
            malware_patterns: vec![
                Regex::new(r"(?i)(\.exe)").unwrap(),
                Regex::new(r"(?i)(\.bat)").unwrap(),
                Regex::new(r"(?i)(\.vbs)").unwrap(),
                Regex::new(r"(?i)(\.js)").unwrap(),
                Regex::new(r"(?i)(\.ps1)").unwrap(),
                Regex::new(r"(?i)(\.sh)").unwrap(),
                Regex::new(r"(?i)(\.dll)").unwrap()
            ],
            script_patterns: vec![
                Regex::new(r"(?i)<script[^>]*>.*?</script>").unwrap(),
                Regex::new(r"(?i)javascript:").unwrap(),
                Regex::new(r"(?i)onload=").unwrap(),
                Regex::new(r"(?i)onerror=").unwrap(),
                Regex::new(r"(?i)onclick=").unwrap()
            ],
            encryption_patterns: vec![
                // Match encryption in potentially dangerous code contexts
                Regex::new(
                    r"(?i)(?:eval|exec|system|shell_exec).*?(?:md5|sha1|sha256|sha512|aes|des|rsa|blowfish)"
                ).unwrap(),
                // Match encryption in script tags
                Regex::new(
                    r"(?i)<script.*?(?:md5|sha1|sha256|sha512|aes|des|rsa|blowfish).*?</script>"
                ).unwrap(),
                // Match encryption in URLs
                Regex::new(
                    r"(?i)https?://.*?(?:md5|sha1|sha256|sha512|aes|des|rsa|blowfish)"
                ).unwrap()
            ],
            max_file_size,
            deep_scan,
            virus_checker,
        })
    }

    fn check_text(&self, content: &str) -> Vec<String> {
        let mut issues = Vec::new();

        // Check for suspicious patterns
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(content) {
                issues.push(format!("Suspicious code pattern found: {}", pattern));
            }
        }

        // Check for advertisements
        for pattern in &self.ad_patterns {
            if pattern.is_match(content) {
                issues.push(format!("Advertisement pattern found: {}", pattern));
            }
        }

        // Check for malware patterns
        for pattern in &self.malware_patterns {
            if pattern.is_match(content) {
                issues.push(format!("Potential malware pattern found: {}", pattern));
            }
        }

        // Check for script patterns
        for pattern in &self.script_patterns {
            if pattern.is_match(content) {
                issues.push(format!("Suspicious script found: {}", pattern));
            }
        }

        // Check for encryption patterns
        for pattern in &self.encryption_patterns {
            if pattern.is_match(content) {
                issues.push(format!("Encryption pattern found: {}", pattern));
            }
        }

        issues
    }

    fn check_file_size(&self, path: &PathBuf) -> Result<()> {
        info!("Checking file size for: {}", path.display());
        let metadata = std::fs::metadata(path)?;
        let size_mb = metadata.len() / (1024 * 1024);

        if size_mb > self.max_file_size {
            warn!("File size {} MB exceeds maximum limit of {} MB", size_mb, self.max_file_size);
            return Err(
                anyhow::anyhow!("File size exceeds maximum limit of {} MB", self.max_file_size)
            );
        }

        info!("File size check passed: {} MB", size_mb);
        Ok(())
    }

    async fn check_file(&self, path: &PathBuf) -> Result<Vec<String>> {
        info!("Starting file check for: {}", path.display());
        let mut issues = Vec::new();

        // Check file size first
        self.check_file_size(path)?;

        // Check with VirusTotal if enabled
        if let Some(checker) = &self.virus_checker {
            info!("Running virus check");
            if let Ok(vt_issues) = checker.check_file(path).await {
                issues.extend(vt_issues);
            }
        }

        if let Some(ext) = path.extension() {
            match ext.to_string_lossy().to_lowercase().as_str() {
                "epub" => {
                    info!("Processing EPUB file");
                    let file = File::open(path)?;
                    let mut archive = ZipArchive::new(file)?;

                    // Check for suspicious file names
                    let mut seen_files = HashSet::new();
                    for i in 0..archive.len() {
                        let mut file = archive.by_index(i)?;
                        let name = file.name().to_lowercase();

                        // Check for duplicate files
                        if !seen_files.insert(name.clone()) {
                            warn!("Duplicate file found: {}", name);
                            issues.push(format!("Duplicate file found: {}", name));
                        }

                        // Check for suspicious file extensions
                        if
                            name.ends_with(".exe") ||
                            name.ends_with(".bat") ||
                            name.ends_with(".vbs")
                        {
                            warn!("Suspicious file found in EPUB: {}", name);
                            issues.push(format!("Suspicious file found in EPUB: {}", name));
                        }

                        if name.ends_with(".html") || name.ends_with(".xhtml") {
                            info!("Checking content in: {}", name);
                            let mut content = String::new();
                            file.read_to_string(&mut content)?;
                            issues.extend(self.check_text(&content));

                            // Deep scan: check for obfuscated content
                            if self.deep_scan {
                                if content.contains("\\u") || content.contains("\\x") {
                                    warn!("Potential obfuscated content found in: {}", name);
                                    issues.push("Potential obfuscated content found".to_string());
                                }
                            }
                        }
                    }
                }
                "txt" => {
                    info!("Processing TXT file");
                    let file = File::open(path)?;
                    let reader = BufReader::new(file);
                    for (line_num, line) in reader.lines().enumerate() {
                        let line = line?;
                        let line_issues = self.check_text(&line);
                        if !line_issues.is_empty() {
                            warn!("Issues found in line {}: {:?}", line_num + 1, line_issues);
                        }
                        issues.extend(line_issues);

                        // Deep scan: check for binary content
                        if self.deep_scan {
                            if line.contains('\0') || line.chars().any(|c| !c.is_ascii()) {
                                warn!("Potential binary content found in line {}", line_num + 1);
                                issues.push("Potential binary content found".to_string());
                            }
                        }
                    }
                }
                _ => {
                    error!("Unsupported file type: {}", ext.to_string_lossy());
                    return Err(anyhow::anyhow!("Unsupported file type"));
                }
            }
        }

        info!("File check completed with {} issues found", issues.len());
        Ok(issues)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.web {
        println!("Starting web server at http://127.0.0.1:8080");
        return web_server::run_web_server().await.map_err(Into::into);
    }

    // CLI mode
    let path = args.path.ok_or_else(|| anyhow::anyhow!("Path is required in CLI mode"))?;
    let file_type = args.file_type.ok_or_else(||
        anyhow::anyhow!("File type is required in CLI mode")
    )?;

    let security_check = SecurityCheck::new(args.max_size, args.deep_scan, args.virus_scan)?;
    let pb = ProgressBar::new_spinner();

    println!("Starting security check...");

    if path.is_file() {
        pb.set_message(format!("Checking file: {}", path.display()));
        match security_check.check_file(&path).await {
            Ok(issues) => {
                if issues.is_empty() {
                    println!("✅ File appears to be secure!");
                } else {
                    println!("⚠️ Found potential security issues:");
                    for issue in issues {
                        println!("- {}", issue);
                    }
                }
            }
            Err(e) => println!("Error checking file: {}", e),
        }
    } else if path.is_dir() {
        pb.set_message(format!("Scanning directory: {}", path.display()));
        for entry in WalkDir::new(&path)
            .into_iter()
            .filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext.to_string_lossy() == file_type {
                        pb.set_message(format!("Checking: {}", path.display()));
                        match security_check.check_file(&path.to_path_buf()).await {
                            Ok(issues) => {
                                if !issues.is_empty() {
                                    println!("\n⚠️ Issues found in {}:", path.display());
                                    for issue in issues {
                                        println!("- {}", issue);
                                    }
                                }
                            }
                            Err(e) => println!("Error checking {}: {}", path.display(), e),
                        }
                    }
                }
            }
        }
    }

    pb.finish_with_message("Security check completed!");
    Ok(())
}
