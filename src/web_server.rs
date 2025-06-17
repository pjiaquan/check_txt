use actix_files as fs;
use actix_multipart::Multipart;
use actix_web::{ web, App, Error, HttpResponse, HttpServer, Responder };
use futures::{ StreamExt, TryStreamExt };
use serde::{ Deserialize, Serialize };
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::time::{ timeout, Duration };
use crate::SecurityCheck;
use log::{ info, error, warn };
use zip::ZipArchive;
use std::io::Read;
use html2text::from_read;
use std::fs::File as StdFile;
use anyhow::anyhow;
use urlencoding;
use base64::{ Engine as _, engine::general_purpose::STANDARD as BASE64 };

const CHECK_TIMEOUT: Duration = Duration::from_secs(30); // 30 seconds timeout

#[derive(Serialize)]
struct CheckResponse {
    secure: bool,
    issues: Vec<String>,
    message: String,
    details: Option<String>,
}

#[derive(Deserialize)]
struct CheckRequest {
    file_type: String,
    deep_scan: bool,
    virus_scan: bool,
    max_size: u64,
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body(include_str!("../static/index.html"))
}

async fn check_file(
    mut payload: Multipart,
    security_check: web::Data<Arc<Mutex<SecurityCheck>>>
) -> Result<HttpResponse, Error> {
    info!("check_file handler called");
    info!("Received file upload request");

    // Create temp directory if it doesn't exist
    let temp_dir = Path::new("temp");
    if !temp_dir.exists() {
        std::fs::create_dir(temp_dir)?;
    }

    let mut file_processed = false;
    let mut response = None;

    // Process each field in the form
    while let Ok(Some(mut field)) = payload.try_next().await {
        if file_processed {
            continue; // Skip additional fields after processing the first file
        }

        let content_disposition = field.content_disposition();
        let filename = content_disposition
            .get_filename()
            .map(ToString::to_string)
            .unwrap_or_else(|| String::from("unknown"));

        info!("Processing file: {}", filename);

        let filepath = temp_dir.join(&filename);
        let filepath_clone = filepath.clone();
        let mut f = web::block(move || std::fs::File::create(&filepath)).await??;
        info!("Created file handle");

        // Read file content
        let mut content = Vec::new();
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            content.extend_from_slice(&data);
        }
        info!("Read {} bytes from upload", content.len());

        if filename == "unknown" || content.is_empty() {
            warn!("No valid file uploaded: filename='{}', size={}", filename, content.len());
            response = Some(
                HttpResponse::BadRequest().json(
                    serde_json::json!({
                    "error": "No valid file uploaded. Please select a file to check."
                })
                )
            );
            break;
        }

        if !filename.to_lowercase().ends_with(".epub") {
            warn!("Uploaded file does not have .epub extension: '{}'", filename);
            response = Some(
                HttpResponse::BadRequest().json(
                    serde_json::json!({
                    "error": "Uploaded file is not an EPUB file. Please upload a .epub file."
                })
                )
            );
            break;
        }

        // Write content to file
        f.write_all(&content)?;
        info!("Wrote content to file");

        // Determine file type from extension
        let file_type = if filename.to_lowercase().ends_with(".epub") {
            "epub"
        } else if filename.to_lowercase().ends_with(".txt") {
            "txt"
        } else {
            warn!("Unsupported file type for file: {}", filename);
            response = Some(
                HttpResponse::BadRequest().json(
                    serde_json::json!({
                    "error": "Unsupported file type. Only .epub and .txt files are supported."
                })
                )
            );
            break;
        };
        info!("Detected file type: {}", file_type);

        // Check file
        info!("Starting security check for file: {}", filename);
        let checker = security_check.lock().await;
        match checker.check_file(&filepath_clone).await {
            Ok(issues) => {
                info!("Security check completed for file: {}", filename);
                // Clean up temp file
                if let Err(e) = std::fs::remove_file(&filepath_clone) {
                    warn!("Failed to remove temp file: {}", e);
                }
                response = Some(
                    HttpResponse::Ok().json(
                        serde_json::json!({
                        "filename": filename,
                        "secure": issues.is_empty(),
                        "issues": issues,
                        "message": if issues.is_empty() { "File appears to be secure" } else { "Found potential security issues" },
                        "details": format!("Checked {} bytes", content.len())
                    })
                    )
                );
            }
            Err(e) => {
                error!("Error checking file {}: {}", filename, e);
                // Clean up temp file
                if let Err(e) = std::fs::remove_file(&filepath_clone) {
                    warn!("Failed to remove temp file: {}", e);
                }
                response = Some(
                    HttpResponse::InternalServerError().json(
                        serde_json::json!({
                        "error": format!("Error checking file: {}", e)
                    })
                    )
                );
            }
        }
        file_processed = true;
    }

    Ok(
        response.unwrap_or_else(||
            HttpResponse::BadRequest().json(
                serde_json::json!({
            "error": "No file uploaded"
        })
            )
        )
    )
}

async fn convert_epub_to_txt(mut payload: Multipart) -> Result<HttpResponse, Error> {
    info!("convert_epub_to_txt handler called");

    // Create temp directory if it doesn't exist
    let temp_dir = Path::new("temp");
    if !temp_dir.exists() {
        std::fs::create_dir(temp_dir)?;
    }

    let mut epub_path = None;

    // Process the uploaded file
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        let filename = content_disposition
            .get_filename()
            .map(ToString::to_string)
            .unwrap_or_else(|| String::from("unknown"));

        if !filename.to_lowercase().ends_with(".epub") {
            return Ok(
                HttpResponse::BadRequest().json(
                    serde_json::json!({
                    "error": "Please upload an EPUB file"
                })
                )
            );
        }

        let filepath = temp_dir.join(&filename);
        let filepath_clone = filepath.clone();
        let mut f = web::block(move || std::fs::File::create(&filepath)).await??;

        // Read and write file content
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            f.write_all(&data)?;
        }

        epub_path = Some(filepath_clone);
        break;
    }

    if let Some(path) = epub_path {
        // Convert EPUB to TXT
        let path_for_cleanup = path.clone();
        let original_filename = path_for_cleanup
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        info!("Processing file: {}", original_filename);

        let txt_content = web
            ::block(move || {
                let file = StdFile::open(&path)?;
                let mut archive = ZipArchive::new(file)?;
                let mut content = String::new();

                // First collect all HTML/XHTML files with their names
                let mut html_files: Vec<(String, usize)> = Vec::new();
                for i in 0..archive.len() {
                    let file = archive.by_index(i)?;
                    let name = file.name().to_lowercase();
                    if name.ends_with(".html") || name.ends_with(".xhtml") {
                        html_files.push((name, i));
                    }
                }

                // Sort files by name to ensure correct chapter order
                html_files.sort_by(|a, b| a.0.cmp(&b.0));

                // Process files in sorted order
                for (name, index) in html_files {
                    // Skip navigation and metadata files
                    if name.contains("nav") || name.contains("toc") || name.contains("metadata") {
                        continue;
                    }

                    let mut file = archive.by_index(index)?;
                    let mut html_content = String::new();
                    file.read_to_string(&mut html_content)?;

                    // Convert HTML to text with better formatting
                    let text = from_read(html_content.as_bytes(), 100);
                    content.push_str(&text);
                    content.push_str("\n\n---\n\n"); // Add separator between chapters
                }
                Ok::<String, std::io::Error>(content)
            }).await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))??;

        // Clean up the EPUB file
        if let Err(e) = std::fs::remove_file(&path_for_cleanup) {
            warn!("Failed to remove temp file: {}", e);
        }

        // Return the TXT content
        let filename = original_filename.trim_end_matches(".epub").to_string() + ".txt";

        info!("Final filename: {}", filename);
        let encoded_filename = urlencoding::encode(&filename);
        info!("Encoded filename: {}", encoded_filename);

        Ok(
            HttpResponse::Ok()
                .content_type("text/plain; charset=utf-8")
                .append_header((
                    "Content-Disposition",
                    format!("attachment; filename*=UTF-8''{}", encoded_filename),
                ))
                .append_header(("Access-Control-Expose-Headers", "Content-Disposition"))
                .body(txt_content)
        )
    } else {
        Ok(
            HttpResponse::BadRequest().json(
                serde_json::json!({
                "error": "No file uploaded"
            })
            )
        )
    }
}

pub async fn run_web_server() -> std::io::Result<()> {
    env_logger::init();

    // Get configuration from environment variables with defaults
    let max_file_size = std::env
        ::var("MAX_FILE_SIZE")
        .unwrap_or_else(|_| "100".to_string())
        .parse::<u64>()
        .expect("MAX_FILE_SIZE must be a number");
    let deep_scan = std::env
        ::var("DEEP_SCAN")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .expect("DEEP_SCAN must be a boolean");
    let virus_scan = std::env
        ::var("VIRUS_SCAN")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .expect("VIRUS_SCAN must be a boolean");

    let security_check = Arc::new(
        Mutex::new(
            SecurityCheck::new(max_file_size, deep_scan, virus_scan).expect(
                "Failed to create SecurityCheck"
            )
        )
    );

    // Get host and port from environment variables with defaults
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env
        ::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a number");

    HttpServer::new(move || {
        App::new()
            .app_data(web::PayloadConfig::new((max_file_size * 1024 * 1024) as usize)) // Convert MB to bytes and to usize
            .app_data(web::Data::new(security_check.clone()))
            .route("/", web::get().to(index))
            .route("/check", web::post().to(check_file))
            .route("/convert", web::post().to(convert_epub_to_txt))
    })
        .bind((host, port))?
        .run().await
}
