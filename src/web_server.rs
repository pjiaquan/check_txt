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
use crate::{ EpubSanitizer, SanitizationMethod };

const CHECK_TIMEOUT: Duration = Duration::from_secs(30); // 30 seconds timeout

// Helper function to ensure temp directory exists with proper permissions
fn ensure_temp_dir() -> Result<std::path::PathBuf, std::io::Error> {
    let temp_dir = Path::new("temp");

    // Create directory if it doesn't exist
    if !temp_dir.exists() {
        std::fs::create_dir_all(temp_dir)?;
        info!("Created temp directory: {}", temp_dir.display());
    }

    // Test write permissions
    let test_file = temp_dir.join(".write_test");
    match std::fs::write(&test_file, b"test") {
        Ok(_) => {
            // Clean up test file
            let _ = std::fs::remove_file(&test_file);
            info!("Temp directory is writable: {}", temp_dir.display());
        }
        Err(e) => {
            error!("Temp directory is not writable: {} - Error: {}", temp_dir.display(), e);
            return Err(e);
        }
    }

    Ok(temp_dir.to_path_buf())
}

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

    // Ensure temp directory exists with proper permissions
    let temp_dir = match ensure_temp_dir() {
        Ok(dir) => dir,
        Err(e) => {
            error!("Failed to create/access temp directory: {}", e);
            return Ok(
                HttpResponse::InternalServerError().json(
                    serde_json::json!({
                    "error": format!("Server configuration error: {}", e)
                })
                )
            );
        }
    };

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

        // Apply Docker-specific file handling fixes only in Docker environment
        let is_docker =
            std::env::var("DOCKER_CONTAINER").is_ok() ||
            std::env::var("container").is_ok() ||
            std::path::Path::new("/.dockerenv").exists();

        if is_docker {
            // **DOCKER COMPATIBILITY FIX**: Explicitly sync the file to disk before closing
            f.sync_all()?;
            drop(f); // Explicitly close the file handle

            // Give the system a moment to fully release the file handle
            std::thread::sleep(std::time::Duration::from_millis(10));

            // Verify file integrity after write (Docker-specific check)
            let written_size = std::fs::metadata(&filepath_clone)?.len();
            if written_size != (content.len() as u64) {
                error!(
                    "File integrity check failed: expected {} bytes, but file on disk has {} bytes",
                    content.len(),
                    written_size
                );
                return Ok(
                    HttpResponse::InternalServerError().json(
                        serde_json::json!({
                        "error": format!("File upload integrity check failed. Expected {} bytes but got {} bytes on disk.", content.len(), written_size)
                    })
                    )
                );
            }
            info!("File integrity verified: {} bytes written and synced to disk", written_size);
        } else {
            // Native Windows/Linux - use simple file handling
            drop(f); // Just close the file normally
            info!("File written successfully: {} bytes", content.len());
        }

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

    // Ensure temp directory exists with proper permissions
    let temp_dir = match ensure_temp_dir() {
        Ok(dir) => dir,
        Err(e) => {
            error!("Failed to create/access temp directory: {}", e);
            return Ok(
                HttpResponse::InternalServerError().json(
                    serde_json::json!({
                    "error": format!("Server configuration error: {}", e)
                })
                )
            );
        }
    };

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

        // Collect all file data first
        let mut file_data = Vec::new();
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            file_data.extend_from_slice(&data);
        }

        // Write the complete file in a blocking operation to ensure it's fully written
        let filepath_for_write = filepath_clone.clone();
        let write_result = web::block(move || {
            std::fs::write(&filepath_for_write, &file_data)
        }).await?;

        match write_result {
            Ok(_) => {
                let file_metadata = std::fs::metadata(&filepath_clone)?;
                info!(
                    "Convert function - File written successfully: {} bytes, permissions: {:?}",
                    file_metadata.len(),
                    file_metadata.permissions()
                );
            }
            Err(e) => {
                error!("Failed to write file: {}", e);
                return Ok(
                    HttpResponse::InternalServerError().json(
                        serde_json::json!({
                        "error": format!("Failed to write uploaded file: {}", e)
                    })
                    )
                );
            }
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

async fn sanitize_epub(
    mut payload: Multipart,
    security_check: web::Data<Arc<Mutex<SecurityCheck>>>
) -> Result<HttpResponse, Error> {
    info!("sanitize_epub handler called");

    // Ensure temp directory exists with proper permissions
    let temp_dir = match ensure_temp_dir() {
        Ok(dir) => dir,
        Err(e) => {
            error!("Failed to create/access temp directory: {}", e);
            return Ok(
                HttpResponse::InternalServerError().json(
                    serde_json::json!({
                    "error": format!("Server configuration error: {}", e)
                })
                )
            );
        }
    };

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

        // Collect all file data first
        let mut file_data = Vec::new();
        while let Some(chunk) = field.next().await {
            let data = chunk?;
            file_data.extend_from_slice(&data);
        }

        // Write the complete file in a blocking operation to ensure it's fully written
        let filepath_for_write = filepath_clone.clone();
        let write_result = web::block(move || {
            std::fs::write(&filepath_for_write, &file_data)
        }).await?;

        match write_result {
            Ok(_) => {
                let file_metadata = std::fs::metadata(&filepath_clone)?;
                info!(
                    "Sanitize function - File written successfully: {} bytes, permissions: {:?}",
                    file_metadata.len(),
                    file_metadata.permissions()
                );
            }
            Err(e) => {
                error!("Failed to write file: {}", e);
                return Ok(
                    HttpResponse::InternalServerError().json(
                        serde_json::json!({
                        "error": format!("Failed to write uploaded file: {}", e)
                    })
                    )
                );
            }
        }

        epub_path = Some(filepath_clone);
        break;
    }

    if let Some(input_path) = epub_path {
        let path_for_cleanup = input_path.clone();
        let original_filename = path_for_cleanup
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        info!("Processing file for sanitization: {}", original_filename);

        // Perform security check on the uploaded EPUB file before sanitization
        info!("Running security check on uploaded EPUB file");
        let security_result = {
            let checker = security_check.lock().await;
            checker.check_file(&input_path).await
        };

        match security_result {
            Ok(issues) => {
                if !issues.is_empty() {
                    info!(
                        "Security issues found in EPUB file (will be addressed by sanitization): {:?}",
                        issues
                    );
                } else {
                    info!("No security issues detected in uploaded EPUB file");
                }
            }
            Err(e) => {
                error!("Security check failed: {}", e);
                // Clean up the input file
                if let Err(e) = std::fs::remove_file(&path_for_cleanup) {
                    warn!("Failed to remove temp input file: {}", e);
                }
                return Ok(
                    HttpResponse::InternalServerError().json(
                        serde_json::json!({
                        "error": format!("Security check failed: {}", e)
                    })
                    )
                );
            }
        }

        // Create output path in temp directory
        let output_filename = format!("{}", original_filename);
        let output_path = temp_dir.join(&output_filename);
        let output_path_clone = output_path.clone();

        // Perform sanitization
        info!("Starting EPUB sanitization");
        let sanitization_result = web::block(move || {
            let sanitizer = EpubSanitizer::new(SanitizationMethod::Remove);
            sanitizer.sanitize_epub(&input_path, &output_path_clone, true)
        }).await;

        // Don't clean up files yet - wait until after we send response to user

        match sanitization_result {
            Ok(Ok(_)) => {
                info!("Sanitization completed successfully");

                // Add a small delay to ensure file is fully written
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                // Check if the output file exists and get its metadata
                match std::fs::metadata(&output_path) {
                    Ok(metadata) => {
                        info!(
                            "Output file exists: {} bytes at path: {}",
                            metadata.len(),
                            output_path.display()
                        );
                    }
                    Err(e) => {
                        error!(
                            "Output file not found at expected path {}: {}",
                            output_path.display(),
                            e
                        );

                        // Try to find the file in current directory or temp subdirectory
                        let current_dir = std::env
                            ::current_dir()
                            .unwrap_or_else(|_| std::path::PathBuf::from("."));
                        let temp_subdir = current_dir.join("temp");

                        info!(
                            "Searching for output file in current directory: {}",
                            current_dir.display()
                        );
                        if let Ok(entries) = std::fs::read_dir(&current_dir) {
                            for entry in entries {
                                if let Ok(entry) = entry {
                                    let path = entry.path();
                                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                        if name.ends_with(".epub") {
                                            info!(
                                                "Found EPUB file in current dir: {}",
                                                path.display()
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        info!(
                            "Searching for output file in temp subdirectory: {}",
                            temp_subdir.display()
                        );
                        if let Ok(entries) = std::fs::read_dir(&temp_subdir) {
                            for entry in entries {
                                if let Ok(entry) = entry {
                                    let path = entry.path();
                                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                        if name.ends_with(".epub") {
                                            info!(
                                                "Found EPUB file in temp subdir: {}",
                                                path.display()
                                            );
                                            // Try to read from this location instead
                                            match std::fs::read(&path) {
                                                Ok(content) => {
                                                    info!(
                                                        "Successfully read sanitized file from: {}",
                                                        path.display()
                                                    );

                                                    let encoded_filename = urlencoding::encode(
                                                        &output_filename
                                                    );

                                                    // Create response first
                                                    let response = HttpResponse::Ok()
                                                        .content_type("application/epub+zip")
                                                        .append_header((
                                                            "Content-Disposition",
                                                            format!("attachment; filename*=UTF-8''{}", encoded_filename),
                                                        ))
                                                        .append_header((
                                                            "Access-Control-Expose-Headers",
                                                            "Content-Disposition",
                                                        ))
                                                        .body(content);

                                                    // Clean up files AFTER creating the response
                                                    if
                                                        let Err(e) = std::fs::remove_file(
                                                            &path_for_cleanup
                                                        )
                                                    {
                                                        warn!("Failed to remove temp input file: {}", e);
                                                    }
                                                    if let Err(e) = std::fs::remove_file(&path) {
                                                        warn!("Failed to remove temp output file: {}", e);
                                                    }

                                                    return Ok(response);
                                                }
                                                Err(e) => {
                                                    error!(
                                                        "Failed to read found file {}: {}",
                                                        path.display(),
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Clean up input file on error
                        if let Err(e) = std::fs::remove_file(&path_for_cleanup) {
                            warn!("Failed to remove temp input file: {}", e);
                        }

                        return Ok(
                            HttpResponse::InternalServerError().json(
                                serde_json::json!({
                                "error": format!("Sanitized file not found at expected location: {}", e)
                            })
                            )
                        );
                    }
                }

                // Read the sanitized file
                match std::fs::read(&output_path) {
                    Ok(sanitized_content) => {
                        info!(
                            "Successfully read sanitized file: {} bytes",
                            sanitized_content.len()
                        );

                        let encoded_filename = urlencoding::encode(&output_filename);

                        // Create response first
                        let response = HttpResponse::Ok()
                            .content_type("application/epub+zip")
                            .append_header((
                                "Content-Disposition",
                                format!("attachment; filename*=UTF-8''{}", encoded_filename),
                            ))
                            .append_header(("Access-Control-Expose-Headers", "Content-Disposition"))
                            .body(sanitized_content);

                        // Clean up files AFTER creating the response
                        if let Err(e) = std::fs::remove_file(&path_for_cleanup) {
                            warn!("Failed to remove temp input file: {}", e);
                        }
                        if let Err(e) = std::fs::remove_file(&output_path) {
                            warn!("Failed to remove temp output file: {}", e);
                        }

                        Ok(response)
                    }
                    Err(e) => {
                        error!(
                            "Failed to read sanitized file from {}: {}",
                            output_path.display(),
                            e
                        );

                        // Clean up files on error
                        if let Err(e) = std::fs::remove_file(&path_for_cleanup) {
                            warn!("Failed to remove temp input file: {}", e);
                        }
                        if let Err(e) = std::fs::remove_file(&output_path) {
                            warn!("Failed to remove temp output file: {}", e);
                        }

                        Ok(
                            HttpResponse::InternalServerError().json(
                                serde_json::json!({
                                "error": format!("Failed to read sanitized file: {}", e)
                            })
                            )
                        )
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Sanitization failed: {}", e);

                // Clean up both input and output files on error
                if let Err(e) = std::fs::remove_file(&path_for_cleanup) {
                    warn!("Failed to remove temp input file: {}", e);
                }
                if let Err(e) = std::fs::remove_file(&output_path) {
                    warn!("Failed to remove temp output file: {}", e);
                }

                Ok(
                    HttpResponse::InternalServerError().json(
                        serde_json::json!({
                        "error": format!("Sanitization failed: {}", e)
                    })
                    )
                )
            }
            Err(e) => {
                error!("Blocking task failed: {}", e);

                // Clean up files on blocking task failure
                if let Err(e) = std::fs::remove_file(&path_for_cleanup) {
                    warn!("Failed to remove temp input file: {}", e);
                }

                Ok(
                    HttpResponse::InternalServerError().json(
                        serde_json::json!({
                        "error": "Internal server error during sanitization"
                    })
                    )
                )
            }
        }
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
            .route("/sanitize", web::post().to(sanitize_epub))
    })
        .bind((host, port))?
        .run().await
}
