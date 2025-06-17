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
use html5ever::parse_document;
use html5ever::tendril::TendrilSink;
use markup5ever_rcdom::{ Handle, NodeData, RcDom };

use std::io::Cursor;
use image::{ ImageFormat, DynamicImage };
use image::io::Reader as ImageReader;
use std::path::Path;
use rqrr;
use zip::write::FileOptions;
use std::io::Write;

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

    /// Sanitize QR codes from EPUB files (remove or blur them)
    #[arg(short, long)]
    sanitize: bool,

    /// Output path for sanitized EPUB (defaults to input_path_sanitized.epub)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Custom advertisement regex pattern to remove (can be used multiple times)
    #[arg(long)]
    ad_pattern: Vec<String>,
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
                    let mut analyzer = EpubAnalyzer::new();
                    if let Err(e) = analyzer.analyze_epub(path) {
                        error!("Error analyzing EPUB: {}", e);
                        issues.push(format!("Error analyzing EPUB: {}", e));
                    } else {
                        analyzer.print_analysis();
                    }

                    // Continue with existing security checks
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

#[derive(Debug)]
struct LinkAnalysis {
    url: String,
    text: String,
    location: String,
}

#[derive(Debug)]
struct QRCodeAnalysis {
    image_path: String,
    location: String,
}

#[derive(Debug)]
struct ImageAnalysis {
    image_path: String,
    location: String,
}

struct EpubAnalyzer {
    links: Vec<LinkAnalysis>,
    qr_codes: Vec<QRCodeAnalysis>,
    images: Vec<ImageAnalysis>,
}

impl EpubAnalyzer {
    fn new() -> Self {
        EpubAnalyzer {
            links: Vec::new(),
            qr_codes: Vec::new(),
            images: Vec::new(),
        }
    }

    fn analyze_image(
        &self,
        archive: &mut ZipArchive<File>,
        image_path: &str,
        location: &str
    ) -> Result<(Vec<String>, Vec<QRCodeAnalysis>), anyhow::Error> {
        let mut issues = Vec::new();
        let mut qr_codes = Vec::new();
        let mut found = false;
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            if file.name() == image_path {
                found = true;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                let img = ImageReader::new(Cursor::new(buffer.clone()))
                    .with_guessed_format()?
                    .decode()?;
                println!("Processing image: {} ({}x{})", image_path, img.width(), img.height());

                if img.width() < 10 || img.height() < 10 {
                    issues.push(format!("Suspicious image size: {}x{}", img.width(), img.height()));
                }

                // QR code detection using rqrr
                // Convert to grayscale first as rqrr expects luma images
                let img_gray = img.to_luma8();
                println!("Attempting QR code detection on grayscale image...");

                let mut found_qr = false;

                // Prepare the image for rqrr
                let mut prepared_img = rqrr::PreparedImage::prepare(img_gray);
                let grids = prepared_img.detect_grids();

                if !grids.is_empty() {
                    println!("Found {} QR code grid(s) in image {}", grids.len(), image_path);
                }

                for grid in grids {
                    match grid.decode() {
                        Ok((_, content)) => {
                            found_qr = true;
                            println!("QR code found in image {}: {}", image_path, content);

                            // Add to QR codes list
                            qr_codes.push(QRCodeAnalysis {
                                image_path: image_path.to_string(),
                                location: location.to_string(),
                            });

                            if content.starts_with("http://") || content.starts_with("https://") {
                                println!("Link found in QR code: {}", content);
                            }
                        }
                        Err(e) => {
                            println!("Error decoding QR code in {}: {}", image_path, e);
                            issues.push(format!("Error decoding QR code in {}: {}", image_path, e));

                            // If we detect a QR code grid but can't decode it, still add it to the analysis
                            // This indicates there IS a QR code present, even if we can't read it
                            if !found_qr {
                                println!("QR code detected but unreadable in image {}", image_path);
                                qr_codes.push(QRCodeAnalysis {
                                    image_path: image_path.to_string(),
                                    location: format!("{} (unreadable)", location),
                                });
                                found_qr = true;
                            }
                        }
                    }
                }

                if !found_qr {
                    println!("No QR codes found in image {}", image_path);
                }
                break;
            }
        }
        if !found {
            issues.push(format!("Image not found in archive: {}", image_path));
        }
        Ok((issues, qr_codes))
    }

    fn analyze_epub(&mut self, path: &PathBuf) -> Result<()> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        // First, find the OPF file to get the content structure
        let mut opf_path = None;
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            if file.name().ends_with(".opf") {
                opf_path = Some(file.name().to_string());
                break;
            }
        }

        // Process HTML/XHTML files
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();

            if name.ends_with(".html") || name.ends_with(".xhtml") {
                let mut content = String::new();
                file.read_to_string(&mut content)?;

                // Parse HTML content
                let dom = parse_document(RcDom::default(), Default::default())
                    .from_utf8()
                    .read_from(&mut content.as_bytes())?;

                // Extract links
                self.extract_links(&dom.document, &name);

                // Look for QR code images
                self.find_qr_codes(&dom.document, &name);
            }
        }

        // Analyze all collected images
        for img in &self.images {
            if
                let Ok((issues, qr_codes)) = self.analyze_image(
                    &mut archive,
                    &img.image_path,
                    &img.location
                )
            {
                if !issues.is_empty() {
                    println!("Issues found in image {}: {:?}", img.image_path, issues);
                }
                self.qr_codes.extend(qr_codes);
            }
        }

        // NEW: Analyze all image files in the archive (not just those referenced in HTML)
        let referenced_images: std::collections::HashSet<String> = self.images
            .iter()
            .map(|img| img.image_path.clone())
            .collect();
        let image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff"];
        let mut unreferenced_images = Vec::new();
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            let name = file.name().to_string();
            if image_extensions.iter().any(|ext| name.to_lowercase().ends_with(ext)) {
                if !referenced_images.contains(&name) {
                    unreferenced_images.push(name);
                }
            }
        }
        // Now analyze the unreferenced images
        for name in unreferenced_images {
            println!("Found unreferenced image in archive: {}", name);
            if
                let Ok((issues, qr_codes)) = self.analyze_image(
                    &mut archive,
                    &name,
                    &"archive only"
                )
            {
                if !issues.is_empty() {
                    println!("Issues found in image {}: {:?}", name, issues);
                }
                self.qr_codes.extend(qr_codes);
            }
            self.images.push(ImageAnalysis {
                image_path: name.clone(),
                location: "archive only".to_string(),
            });
        }

        Ok(())
    }

    fn extract_links(&mut self, handle: &Handle, location: &str) {
        let node = handle;

        match node.data {
            NodeData::Element { ref name, ref attrs, .. } => {
                if name.local.as_ref() == "a" {
                    if
                        let Some(attr) = attrs
                            .borrow()
                            .iter()
                            .find(|attr| attr.name.local.as_ref() == "href")
                    {
                        let url = attr.value.to_string();
                        let text = node.children
                            .borrow()
                            .iter()
                            .filter_map(|child| {
                                if let NodeData::Text { ref contents } = child.data {
                                    Some(contents.borrow().to_string())
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<String>>()
                            .join("")
                            .trim()
                            .to_string();

                        self.links.push(LinkAnalysis {
                            url,
                            text,
                            location: location.to_string(),
                        });
                    }
                }
            }
            _ => {}
        }

        // Recursively process child nodes
        for child in node.children.borrow().iter() {
            self.extract_links(child, location);
        }
    }

    fn find_qr_codes(&mut self, handle: &Handle, location: &str) {
        let node = handle;

        match node.data {
            NodeData::Element { ref name, ref attrs, .. } => {
                if name.local.as_ref() == "img" {
                    if
                        let Some(attr) = attrs
                            .borrow()
                            .iter()
                            .find(|attr| attr.name.local.as_ref() == "src")
                    {
                        let image_path = attr.value.to_string();

                        // Add to images list for general analysis
                        self.images.push(ImageAnalysis {
                            image_path: image_path.clone(),
                            location: location.to_string(),
                        });

                        // Check if this might be a QR code image
                        // This is a simple heuristic - we could make this more sophisticated
                        if
                            image_path.to_lowercase().contains("qr") ||
                            image_path.to_lowercase().contains("qrcode")
                        {
                            self.qr_codes.push(QRCodeAnalysis {
                                image_path,
                                location: location.to_string(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        // Recursively process child nodes
        for child in node.children.borrow().iter() {
            self.find_qr_codes(child, location);
        }
    }

    fn print_analysis(&self) {
        println!("\n=== Link Analysis ===");
        for link in &self.links {
            println!("URL: {}", link.url);
            println!("Text: {}", link.text);
            println!("Location: {}", link.location);
            println!("---");
        }

        println!("\n=== QR Code Analysis ===");
        for qr in &self.qr_codes {
            println!("Image Path: {}", qr.image_path);
            println!("Location: {}", qr.location);
            println!("---");
        }

        println!("\n=== All Images Analysis ===");
        for img in &self.images {
            println!("Image Path: {}", img.image_path);
            println!("Location: {}", img.location);
            println!("---");
        }
    }
}

pub enum SanitizationMethod {
    Remove,
    Blur,
    RemoveText,
    BlurAndRemoveText,
}

pub struct EpubSanitizer {
    method: SanitizationMethod,
    ad_text_patterns: Vec<Regex>,
}

impl EpubSanitizer {
    pub fn new(method: SanitizationMethod) -> Self {
        // Common advertisement patterns
        let ad_text_patterns = vec![
            // Specific Telegram channel pattern
            Regex::new(r"(?i)感谢.*?@sharebooks4you.*?制作.*?欢迎.*?扫码订阅").unwrap(),

            // General Telegram channel patterns
            Regex::new(r"(?i)感谢.*?telegram.*?频道.*?制作").unwrap(),
            Regex::new(r"(?i)欢迎.*?扫码订阅").unwrap(),
            Regex::new(r"(?i)telegram.*?@\w+.*?制作").unwrap(),

            // General advertisement patterns
            Regex::new(r"(?i)感谢.*?制作.*?欢迎").unwrap(),
            Regex::new(r"(?i)本书由.*?制作").unwrap(),
            Regex::new(r"(?i)更多电子书.*?关注").unwrap(),
            Regex::new(r"(?i)扫描.*?二维码.*?关注").unwrap(),
            Regex::new(r"(?i)微信.*?公众号").unwrap(),
            Regex::new(r"(?i)QQ.*?群.*?\d+").unwrap(),

            // English advertisement patterns
            Regex::new(r"(?i)thanks.*?to.*?@\w+.*?for.*?creation").unwrap(),
            Regex::new(r"(?i)welcome.*?scan.*?subscribe").unwrap(),
            Regex::new(r"(?i)made.*?by.*?@\w+").unwrap(),
            Regex::new(r"(?i)follow.*?us.*?@\w+").unwrap()
        ];

        EpubSanitizer {
            method,
            ad_text_patterns,
        }
    }

    fn add_custom_ad_pattern(&mut self, pattern: &str) -> Result<()> {
        match Regex::new(pattern) {
            Ok(regex) => {
                self.ad_text_patterns.push(regex);
                println!("Added custom advertisement pattern: {}", pattern);
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e)),
        }
    }

    fn find_qr_code_images_simple(&self, input_path: &PathBuf) -> Result<HashSet<String>> {
        println!("Scanning for QR code images...");
        let mut qr_code_images = HashSet::new();

        let input_file = File::open(input_path)?;
        let mut archive = ZipArchive::new(input_file)?;

        // Look for image files that might contain QR codes
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            let name = file.name().to_string();

            // Check if this is an image file
            let image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff"];
            if image_extensions.iter().any(|ext| name.to_lowercase().ends_with(ext)) {
                // Simple heuristic: check if filename contains QR-related terms
                // or contains "sharebooks" (from the specific case we're dealing with)
                if
                    name.to_lowercase().contains("qr") ||
                    name.to_lowercase().contains("qrcode") ||
                    name.to_lowercase().contains("sharebooks")
                {
                    println!("Found potential QR code image: {}", name);
                    qr_code_images.insert(name);
                }
            }
        }

        Ok(qr_code_images)
    }

    fn clean_opf_metadata(&self, content: &str) -> String {
        use std::io::BufRead;

        let mut cleaned_content = String::new();
        let mut in_metadata = false;
        let mut skip_current_tag = false;
        let mut tag_level = 0;

        for line in content.lines() {
            let trimmed = line.trim();

            // Track if we're inside the metadata section
            if trimmed.starts_with("<metadata") {
                in_metadata = true;
                cleaned_content.push_str(line);
                cleaned_content.push('\n');
                continue;
            }

            if trimmed.starts_with("</metadata>") {
                in_metadata = false;
                cleaned_content.push_str(line);
                cleaned_content.push('\n');
                continue;
            }

            if in_metadata {
                // Remove advertisement-related metadata tags
                if
                    trimmed.starts_with("<dc:subject>") ||
                    trimmed.starts_with("<meta name=\"tags\"") ||
                    trimmed.starts_with("<meta property=\"tags\"") ||
                    trimmed.starts_with("<dc:description>")
                {
                    // Check if this is a self-closing tag or has content on the same line
                    if trimmed.ends_with("/>") {
                        // Self-closing tag, skip entirely
                        println!("Removing metadata tag: {}", trimmed);
                        continue;
                    } else if let Some(end_pos) = trimmed.find("</") {
                        // Single line with opening and closing tag
                        let tag_content = &trimmed[trimmed.find('>').unwrap_or(0) + 1..end_pos];
                        if
                            tag_content.to_lowercase().contains("advertisement") ||
                            tag_content.to_lowercase().contains("telegram") ||
                            tag_content.to_lowercase().contains("tg频道") ||
                            tag_content.to_lowercase().contains("@share") ||
                            tag_content.to_lowercase().contains("sharebooks") ||
                            tag_content.to_lowercase().contains("关注") ||
                            tag_content.to_lowercase().contains("扫码") ||
                            tag_content.to_lowercase().contains("订阅")
                        {
                            println!("Removing metadata tag with ad content: {}", trimmed);
                            continue;
                        }
                    } else {
                        // Multi-line tag, start tracking
                        skip_current_tag = true;
                        tag_level = 1;

                        // Check if the current line contains advertisement keywords
                        let tag_content = if let Some(start) = trimmed.find('>') {
                            &trimmed[start + 1..]
                        } else {
                            ""
                        };

                        if
                            tag_content.to_lowercase().contains("advertisement") ||
                            tag_content.to_lowercase().contains("telegram") ||
                            tag_content.to_lowercase().contains("tg频道") ||
                            tag_content.to_lowercase().contains("@share") ||
                            tag_content.to_lowercase().contains("sharebooks") ||
                            tag_content.to_lowercase().contains("关注") ||
                            tag_content.to_lowercase().contains("扫码") ||
                            tag_content.to_lowercase().contains("订阅")
                        {
                            println!("Starting to remove multi-line metadata tag: {}", trimmed);
                            continue;
                        } else {
                            skip_current_tag = false;
                        }
                    }
                }

                // Handle multi-line tag removal
                if skip_current_tag {
                    if trimmed.starts_with("</") {
                        tag_level -= 1;
                        if tag_level == 0 {
                            skip_current_tag = false;
                            println!("Finished removing multi-line metadata tag");
                        }
                        continue;
                    } else if trimmed.starts_with("<") && !trimmed.ends_with("/>") {
                        tag_level += 1;
                        continue;
                    } else {
                        // Content line inside tag being removed
                        continue;
                    }
                }
            }

            // Keep all other lines
            cleaned_content.push_str(line);
            cleaned_content.push('\n');
        }

        cleaned_content
    }

    fn clean_advertisement_text(&self, content: &str) -> (String, Vec<String>) {
        let lines: Vec<&str> = content.lines().collect();
        let mut cleaned_lines = Vec::new();
        let mut removed_lines = Vec::new();
        let mut empty_line_count = 0;

        for (line_num, line) in lines.iter().enumerate() {
            let mut line_removed = false;

            // Check if this line matches any advertisement pattern
            for pattern in &self.ad_text_patterns {
                if pattern.is_match(line) {
                    removed_lines.push(format!("Line {}: \"{}\"", line_num + 1, line.trim()));
                    line_removed = true;
                    break;
                }
            }

            if !line_removed {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    empty_line_count += 1;
                    if empty_line_count <= 2 {
                        // Keep at most 2 consecutive empty lines
                        cleaned_lines.push(*line);
                    }
                } else {
                    empty_line_count = 0;
                    cleaned_lines.push(*line);
                }
            }
        }

        (cleaned_lines.join("\n"), removed_lines)
    }

    fn blur_qr_codes_in_image(&self, img: &DynamicImage) -> Result<DynamicImage> {
        let mut img_rgba = img.to_rgba8();
        let (width, height) = img_rgba.dimensions();

        // Convert to grayscale for QR detection
        let img_gray = img.to_luma8();
        let mut prepared_img = rqrr::PreparedImage::prepare(img_gray);
        let grids = prepared_img.detect_grids();

        // If QR codes found, blur those regions
        if !grids.is_empty() {
            println!("Found {} QR code(s) to blur", grids.len());

            for grid in grids {
                // Get the corners of the QR code from bounds field
                let corners = &grid.bounds;

                // Calculate bounding box
                let min_x = corners
                    .iter()
                    .map(|point| point.x as u32)
                    .min()
                    .unwrap_or(0);
                let max_x = corners
                    .iter()
                    .map(|point| point.x as u32)
                    .max()
                    .unwrap_or(width);
                let min_y = corners
                    .iter()
                    .map(|point| point.y as u32)
                    .min()
                    .unwrap_or(0);
                let max_y = corners
                    .iter()
                    .map(|point| point.y as u32)
                    .max()
                    .unwrap_or(height);

                // Add some padding around the QR code
                let padding = 10u32;
                let x1 = min_x.saturating_sub(padding);
                let y1 = min_y.saturating_sub(padding);
                let x2 = (max_x + padding).min(width);
                let y2 = (max_y + padding).min(height);

                // Blur the QR code region
                for y in y1..y2 {
                    for x in x1..x2 {
                        if x < width && y < height {
                            // Simple blur by averaging surrounding pixels
                            let mut r_sum = 0u32;
                            let mut g_sum = 0u32;
                            let mut b_sum = 0u32;
                            let mut count = 0u32;

                            let blur_radius = 3;
                            for dy in -(blur_radius as i32)..=blur_radius {
                                for dx in -(blur_radius as i32)..=blur_radius {
                                    let nx = ((x as i32) + dx)
                                        .max(0)
                                        .min((width as i32) - 1) as u32;
                                    let ny = ((y as i32) + dy)
                                        .max(0)
                                        .min((height as i32) - 1) as u32;

                                    let pixel = img_rgba.get_pixel(nx, ny);
                                    r_sum += pixel[0] as u32;
                                    g_sum += pixel[1] as u32;
                                    b_sum += pixel[2] as u32;
                                    count += 1;
                                }
                            }

                            if count > 0 {
                                let blurred_pixel = image::Rgba([
                                    (r_sum / count) as u8,
                                    (g_sum / count) as u8,
                                    (b_sum / count) as u8,
                                    255u8,
                                ]);
                                img_rgba.put_pixel(x, y, blurred_pixel);
                            }
                        }
                    }
                }
            }
        }

        Ok(DynamicImage::ImageRgba8(img_rgba))
    }

    pub fn sanitize_epub(
        &self,
        input_path: &PathBuf,
        output_path: &PathBuf,
        _force_text_removal: bool
    ) -> Result<()> {
        println!("Starting EPUB sanitization...");

        // Log system information for troubleshooting
        if let Ok(metadata) = std::fs::metadata(input_path) {
            println!("Input file size: {} bytes", metadata.len());
            println!("Input file permissions: {:?}", metadata.permissions());
        }

        // Check available disk space in current directory
        if let Ok(current_dir) = std::env::current_dir() {
            println!("Current working directory: {}", current_dir.display());
        }

        // Detect if we're running in Docker/container environment
        let is_docker =
            std::path::Path::new("/.dockerenv").exists() ||
            std::env::var("DOCKER_CONTAINER").is_ok() ||
            std::env::var("container").is_ok();

        if is_docker {
            println!("Docker environment detected - using compatibility mode");

            // Only validate file header in Docker mode (where we need extra validation)
            let mut file_header = [0u8; 4];
            {
                let mut file = File::open(input_path).map_err(|e|
                    anyhow::anyhow!(
                        "Failed to open input file for validation {}: {}",
                        input_path.display(),
                        e
                    )
                )?;
                use std::io::Read;
                file
                    .read_exact(&mut file_header)
                    .map_err(|e| anyhow::anyhow!("Failed to read file header: {}", e))?;
            }

            // Check ZIP file signature (PK\x03\x04 or PK\x05\x06 for empty archives)
            if !(file_header.starts_with(b"PK\x03\x04") || file_header.starts_with(b"PK\x05\x06")) {
                return Err(
                    anyhow::anyhow!(
                        "File does not appear to be a valid ZIP/EPUB file. Header: {:?}",
                        file_header
                    )
                );
            }
            println!("ZIP file signature validation passed");

            // Docker compatibility mode: Extract all files to memory first
            self.sanitize_epub_docker_mode(input_path, output_path)
        } else {
            println!("Native environment detected - using standard mode");
            // Standard mode: Process files directly from ZIP archive (no extra validation needed)
            self.sanitize_epub_standard_mode(input_path, output_path)
        }
    }

    // Docker compatibility mode - extracts all files to memory first
    fn sanitize_epub_docker_mode(&self, input_path: &PathBuf, output_path: &PathBuf) -> Result<()> {
        println!("Using Docker compatibility mode - extracting all archive contents to memory...");

        let input_file = File::open(input_path).map_err(|e|
            anyhow::anyhow!("Failed to open input file {}: {}", input_path.display(), e)
        )?;

        // Use buffered reader for better performance
        let buffered_reader = std::io::BufReader::with_capacity(64 * 1024, input_file);
        let mut input_archive = ZipArchive::new(buffered_reader).map_err(|e|
            anyhow::anyhow!("Failed to read ZIP archive {}: {}", input_path.display(), e)
        )?;

        let total_files = input_archive.len();
        println!("ZIP archive opened successfully with {} files", total_files);

        // Extract all files into memory first (Docker workaround)
        let mut extracted_files: Vec<(String, Vec<u8>)> = Vec::new();

        for i in 0..total_files {
            let mut file = match input_archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    return Err(
                        anyhow::anyhow!(
                            "Failed to access file at index {} during extraction: {}. This indicates a ZIP library compatibility issue with Docker.",
                            i,
                            e
                        )
                    );
                }
            };

            let file_name = file.name().to_string();
            let file_size = file.size();

            println!("Extracting {}/{}: {} ({} bytes)", i + 1, total_files, file_name, file_size);

            // Validate file size
            if file_size > 50 * 1024 * 1024 {
                return Err(
                    anyhow::anyhow!(
                        "File {} is too large ({} bytes). Maximum size is 50MB per file.",
                        file_name,
                        file_size
                    )
                );
            }

            // Read entire file content into memory
            let mut content = Vec::with_capacity(file_size as usize);

            // Use chunked reading for better Docker compatibility
            let mut total_read = 0;
            let mut buffer = vec![0u8; std::cmp::min(8192, file_size as usize)];

            loop {
                match file.read(&mut buffer) {
                    Ok(0) => {
                        break;
                    } // End of file
                    Ok(n) => {
                        content.extend_from_slice(&buffer[..n]);
                        total_read += n;
                        if total_read % (64 * 1024) == 0 && file_size > 64 * 1024 {
                            println!("  Extracted {} / {} bytes", total_read, file_size);
                        }
                    }
                    Err(e) => {
                        return Err(
                            anyhow::anyhow!(
                                "Failed to read content from file '{}' at byte {} during extraction: {}. Docker ZIP I/O error.",
                                file_name,
                                total_read,
                                e
                            )
                        );
                    }
                }

                if total_read >= (file_size as usize) {
                    break;
                }
            }

            if total_read != (file_size as usize) {
                warn!(
                    "Warning: Expected {} bytes but extracted {} bytes from {}",
                    file_size,
                    total_read,
                    file_name
                );
                content.resize(file_size as usize, 0);
            }

            extracted_files.push((file_name, content));
        }

        println!("Successfully extracted {} files to memory", extracted_files.len());

        // Now process the extracted files and create output archive
        let output_file = File::create(output_path).map_err(|e|
            anyhow::anyhow!("Failed to create output file {}: {}", output_path.display(), e)
        )?;
        let mut output_archive = zip::ZipWriter::new(output_file);

        let mut files_processed = 0;
        let mut metadata_files_cleaned = 0;

        println!("Processing extracted files...");

        for (file_name, mut content) in extracted_files {
            println!("Processing extracted file: {} ({} bytes)", file_name, content.len());

            // Check if this is an OPF file (metadata file)
            if file_name.ends_with(".opf") {
                println!("Found OPF metadata file: {}", file_name);

                // Convert to string for processing
                let content_str = String::from_utf8_lossy(&content);
                let cleaned_content = self.clean_opf_metadata(&content_str);

                if cleaned_content != content_str {
                    println!("Cleaned metadata in file: {}", file_name);
                    metadata_files_cleaned += 1;
                }

                content = cleaned_content.into_bytes();
            }

            // Write file to output archive
            let options = zip::write::FileOptions
                ::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o755);

            output_archive.start_file(&file_name, options)?;
            output_archive.write_all(&content)?;

            files_processed += 1;
        }

        output_archive.finish()?;

        // Ensure the file is fully written and flushed to disk
        drop(output_archive);

        // Add a small delay to ensure file system operations complete
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Verify the output file was created successfully
        match std::fs::metadata(output_path) {
            Ok(metadata) => {
                println!(
                    "Docker mode sanitization completed successfully!\nProcessed {} files, cleaned {} metadata files\nOutput: {} ({} bytes)",
                    files_processed,
                    metadata_files_cleaned,
                    output_path.display(),
                    metadata.len()
                );
            }
            Err(e) => {
                return Err(
                    anyhow::anyhow!(
                        "Sanitization appeared to complete but output file verification failed: {} ({})",
                        output_path.display(),
                        e
                    )
                );
            }
        }

        Ok(())
    }

    // Standard mode - the original working implementation for Windows/native environments
    fn sanitize_epub_standard_mode(
        &self,
        input_path: &PathBuf,
        output_path: &PathBuf
    ) -> Result<()> {
        use std::io::Read;

        println!("Using standard mode - processing files directly from ZIP archive...");

        let input_file = File::open(input_path).map_err(|e|
            anyhow::anyhow!("Failed to open input file {}: {}", input_path.display(), e)
        )?;

        // Use buffered reader for better performance
        let buffered_reader = std::io::BufReader::with_capacity(64 * 1024, input_file);
        let mut input_archive = ZipArchive::new(buffered_reader).map_err(|e|
            anyhow::anyhow!("Failed to read ZIP archive {}: {}", input_path.display(), e)
        )?;

        let total_files = input_archive.len();
        println!("ZIP archive opened successfully with {} files", total_files);

        // Extract all files into memory first (same approach as Docker mode)
        let mut extracted_files: Vec<(String, Vec<u8>)> = Vec::new();

        for i in 0..total_files {
            let mut file = match input_archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    return Err(
                        anyhow::anyhow!(
                            "Failed to access file at index {} during extraction: {}",
                            i,
                            e
                        )
                    );
                }
            };

            let file_name = file.name().to_string();
            let file_size = file.size();

            println!("Extracting {}/{}: {} ({} bytes)", i + 1, total_files, file_name, file_size);

            // Validate file size
            if file_size > 50 * 1024 * 1024 {
                return Err(
                    anyhow::anyhow!(
                        "File {} is too large ({} bytes). Maximum size is 50MB per file.",
                        file_name,
                        file_size
                    )
                );
            }

            // Read entire file content into memory using chunked reading
            let mut content = Vec::with_capacity(file_size as usize);
            let mut total_read = 0;
            let mut buffer = vec![0u8; std::cmp::min(8192, file_size as usize)];

            loop {
                match file.read(&mut buffer) {
                    Ok(0) => {
                        break;
                    } // End of file
                    Ok(n) => {
                        content.extend_from_slice(&buffer[..n]);
                        total_read += n;
                        if total_read % (64 * 1024) == 0 && file_size > 64 * 1024 {
                            println!("  Extracted {} / {} bytes", total_read, file_size);
                        }
                    }
                    Err(e) => {
                        return Err(
                            anyhow::anyhow!(
                                "Failed to read content from file '{}' at byte {} during extraction: {}",
                                file_name,
                                total_read,
                                e
                            )
                        );
                    }
                }

                if total_read >= (file_size as usize) {
                    break;
                }
            }

            if total_read != (file_size as usize) {
                println!(
                    "Warning: Expected {} bytes but extracted {} bytes from {}",
                    file_size,
                    total_read,
                    file_name
                );
                content.resize(file_size as usize, 0);
            }

            extracted_files.push((file_name, content));
        }

        println!("Successfully extracted {} files to memory", extracted_files.len());

        // Now process the extracted files and create output archive
        let output_file = File::create(output_path).map_err(|e|
            anyhow::anyhow!("Failed to create output file {}: {}", output_path.display(), e)
        )?;
        let mut output_archive = zip::ZipWriter::new(output_file);

        let mut files_processed = 0;
        let mut metadata_files_cleaned = 0;

        println!("Processing extracted files...");

        for (file_name, mut content) in extracted_files {
            println!("Processing extracted file: {} ({} bytes)", file_name, content.len());

            // Check if this is an OPF file (metadata file)
            if file_name.ends_with(".opf") {
                println!("Found OPF metadata file: {}", file_name);

                // Convert to string for processing
                let content_str = String::from_utf8_lossy(&content);
                let cleaned_content = self.clean_opf_metadata(&content_str);

                if cleaned_content != content_str {
                    println!("Cleaned metadata in file: {}", file_name);
                    metadata_files_cleaned += 1;
                }

                content = cleaned_content.into_bytes();
            }

            // Write file to output archive
            let options = zip::write::FileOptions
                ::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o755);

            output_archive.start_file(&file_name, options)?;
            output_archive.write_all(&content)?;

            files_processed += 1;
        }

        output_archive.finish()?;

        // Ensure the file is fully written and flushed to disk
        drop(output_archive);

        // Add a small delay to ensure file system operations complete
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Verify the output file was created successfully
        match std::fs::metadata(output_path) {
            Ok(metadata) => {
                println!(
                    "Sanitization completed successfully!\nProcessed {} files, cleaned {} metadata files\nOutput: {} ({} bytes)",
                    files_processed,
                    metadata_files_cleaned,
                    output_path.display(),
                    metadata.len()
                );
            }
            Err(e) => {
                return Err(
                    anyhow::anyhow!(
                        "Sanitization appeared to complete but output file verification failed: {} ({})",
                        output_path.display(),
                        e
                    )
                );
            }
        }

        Ok(())
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

    // Handle sanitization mode
    if args.sanitize {
        if file_type != "epub" {
            return Err(anyhow::anyhow!("Sanitization is only supported for EPUB files"));
        }

        if !path.is_file() {
            return Err(
                anyhow::anyhow!("Sanitization requires a single EPUB file, not a directory")
            );
        }

        // Generate output path if not provided
        let has_custom_output = args.output.is_some();
        let output_path = if let Some(output) = args.output {
            output
        } else {
            let mut output = path.clone();
            let stem = output
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("sanitized");
            output.set_file_name(format!("{}.epub", stem));
            output
        };

        println!("Sanitizing EPUB: {} -> {}", path.display(), output_path.display());

        let method = if has_custom_output {
            // If user provided output path, use default comprehensive cleaning
            println!(
                "Using default comprehensive sanitization: Remove QR code images completely + Remove all advertisement text"
            );
            SanitizationMethod::Remove // We'll handle text removal separately for this case
        } else {
            // Ask user for sanitization method only if no output path was provided
            println!("Choose sanitization method:");
            println!("1. Blur QR codes (recommended)");
            println!("2. Remove images with QR codes completely");
            println!("3. Remove advertisement text from content");
            println!("4. Blur QR codes and remove advertisement text");
            println!("Enter choice (1, 2, 3, or 4): ");

            use std::io;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let choice = input.trim();

            match choice {
                "1" => SanitizationMethod::Blur,
                "2" => SanitizationMethod::Remove,
                "3" => SanitizationMethod::RemoveText,
                "4" => SanitizationMethod::BlurAndRemoveText,
                _ => {
                    println!("Invalid choice, defaulting to blur method");
                    SanitizationMethod::Blur
                }
            }
        };

        let mut sanitizer = EpubSanitizer::new(method);

        // Add custom advertisement patterns if provided
        for pattern in &args.ad_pattern {
            match sanitizer.add_custom_ad_pattern(pattern) {
                Ok(_) => {}
                Err(e) => {
                    println!("Warning: {}", e);
                }
            }
        }

        sanitizer.sanitize_epub(&path, &output_path, has_custom_output)?;

        return Ok(());
    }

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
