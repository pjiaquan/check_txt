# Check TXT - File Security Checker

A powerful file security checker for TXT and EPUB files with virus scanning capabilities, QR code detection, and advertisement text removal.

## 🚀 **Quick Start - Remove Advertisement Text**

```bash
# Automatic comprehensive cleaning when output path is provided
# This will: Remove QR code images completely + Remove all advertisement text
cargo run -- -p book.epub -f epub --sanitize -o clean_book.epub

# Interactive mode (when no output path provided)
cargo run -- -p book.epub -f epub --sanitize
```

**New Behavior:** When you provide an output path (`-o` or `--output`), the tool automatically uses the most comprehensive sanitization method: **Remove QR code images completely + Remove all advertisement text** (including the Telegram channel ad: '感谢Telegram 频道 @sharebooks4you制作，欢迎大家扫码订阅').

<div align="center">
  <img src="logo.png" alt="Check TXT Logo" width="200"/>
</div>

[English](#english) | [中文](#chinese)

---

## English

### Overview

Check TXT is a powerful Rust-based file security checker designed to analyze text files, EPUB files, and other document formats for potential security threats, malicious content, and suspicious patterns. It provides both command-line interface (CLI) and web-based interface for easy file analysis.

### Features

- **Multi-format Support**: Check TXT, EPUB files for security issues
- **Comprehensive Scanning**: Detects suspicious code patterns, advertisements, malware indicators, and encryption patterns
- **VirusTotal Integration**: Optional virus scanning using VirusTotal API
- **Deep Scan Mode**: Enhanced scanning for obfuscated content and binary data
- **Web Interface**: User-friendly web-based file upload and analysis
- **File Size Control**: Configurable maximum file size limits
- **Progress Tracking**: Real-time progress indicators for long operations
- **EPUB to TXT Conversion**: Convert EPUB files to plain text format
- **File Security Scanning**: Detects suspicious patterns, malware signatures, and potentially dangerous content
- **Virus Scanning**: Integration with VirusTotal API for comprehensive virus detection
- **EPUB Analysis**: Deep analysis of EPUB files including:
  - Link extraction and analysis
  - QR code detection in images
  - Image analysis and processing
  - Advertisement text detection and removal
- **QR Code Sanitization**: Remove or blur QR codes from EPUB images
- **Advertisement Text Removal**: Remove advertisement text patterns from EPUB content
- **Flexible Configuration**: Customizable patterns and scanning options

### Security Checks

The tool performs comprehensive security analysis including:

- **Suspicious Code Patterns**: Detects eval(), exec(), system() calls and other dangerous functions
- **Advertisement Detection**: Identifies common advertising patterns and promotional content
- **Malware Indicators**: Scans for executable files, scripts, and other potentially harmful content
- **Script Analysis**: Detects embedded JavaScript and other scripting languages
- **Encryption Patterns**: Identifies encryption algorithms in potentially dangerous contexts
- **File Integrity**: Checks for duplicate files and suspicious file extensions in archives

### Installation

#### Prerequisites

- Rust (latest stable version)
- Cargo package manager

#### Build from Source

```bash
# Clone the repository
git clone <repository-url>
cd check_txt

# Build the project
cargo build --release

# The binary will be available at target/release/check_txt
```

#### Docker (Optional)

```bash
# Build Docker image
docker build -t check_txt .

# Run with Docker Compose
docker-compose up
```

### Configuration

#### Environment Variables

Create a `.env` file in the project root:

```env
# Required for virus scanning
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

#### VirusTotal API Key

To enable virus scanning functionality:

1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Get your API key from the account settings
3. Add it to your `.env` file

### Usage

#### Command Line Interface

```bash
# Check a single file
check_txt --path /path/to/file.txt --file-type txt

# Check a directory of files
check_txt --path /path/to/directory --file-type txt

# Enable deep scanning
check_txt --path /path/to/file.epub --file-type epub --deep-scan

# Enable virus scanning
check_txt --path /path/to/file.txt --file-type txt --virus-scan

# Set custom file size limit (in MB)
check_txt --path /path/to/file.txt --file-type txt --max-size 50

# Start web server
check_txt --web
```

#### Web Interface

1. Start the web server:
   ```bash
   check_txt --web
   ```

2. Open your browser and navigate to `http://127.0.0.1:8090`

3. Upload files through the web interface for analysis

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--path` | `-p` | Path to file or directory to check | Required |
| `--file-type` | `-f` | File type to check (txt, epub) | Required |
| `--max-size` | `-m` | Maximum file size in MB | 100 |
| `--deep-scan` | `-d` | Enable deep scanning | false |
| `--virus-scan` | `-v` | Enable virus scanning | false |
| `--web` | `-w` | Start web server | false |

### Examples

#### Basic File Check
```bash
check_txt --path document.txt --file-type txt
```

#### Comprehensive EPUB Analysis
```bash
check_txt --path book.epub --file-type epub --deep-scan --virus-scan --max-size 200
```

#### Directory Scanning
```bash
check_txt --path ./documents --file-type txt --deep-scan
```

### Output Examples

#### Secure File
```
✅ File appears to be secure!
```

#### File with Issues
```
⚠️ Found potential security issues:
- Suspicious code pattern found: (?i)(eval\s*\()
- Advertisement pattern found: (?i)(click here)
- Potential malware pattern found: (?i)(\.exe)
```

### Project Structure

```
check_txt/
├── src/
│   ├── main.rs          # Main CLI application
│   ├── virus_check.rs   # VirusTotal integration
│   └── web_server.rs    # Web server implementation
├── static/
│   └── index.html       # Web interface
├── temp/                # Temporary file storage
├── Cargo.toml          # Rust dependencies
├── Dockerfile          # Docker configuration
└── docker-compose.yml  # Docker Compose setup
```

### Dependencies

- **actix-web**: Web framework for the web interface
- **clap**: Command-line argument parsing
- **reqwest**: HTTP client for API calls
- **serde**: Serialization/deserialization
- **tokio**: Async runtime
- **walkdir**: Directory traversal
- **regex**: Regular expression matching
- **zip**: Archive file handling
- **sha2**: Cryptographic hashing
- **indicatif**: Progress indicators

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Chinese

### 概述

Check TXT 是一个基于 Rust 的强大文件安全检查器，专为分析文本文件、EPUB 文件和其他文档格式中的潜在安全威胁、恶意内容和可疑模式而设计。它提供命令行界面（CLI）和基于 Web 的界面，方便进行文件分析。

### 功能特性

- **多格式支持**：检查 TXT、EPUB 文件的安全问题
- **全面扫描**：检测可疑代码模式、广告、恶意软件指标和加密模式
- **VirusTotal 集成**：使用 VirusTotal API 进行可选的病毒扫描
- **深度扫描模式**：增强扫描以检测混淆内容和二进制数据
- **Web 界面**：用户友好的基于 Web 的文件上传和分析
- **文件大小控制**：可配置的最大文件大小限制
- **进度跟踪**：长时间操作的实时进度指示器
- **EPUB 转 TXT 转换**：将 EPUB 文件转换为纯文本格式
- **文件安全扫描**：检测可疑模式、恶意软件签名和潜在危险内容
- **病毒扫描**：与 VirusTotal API 集成进行全面病毒检测
- **EPUB 分析**：深入分析 EPUB 文件，包括：
  - 链接提取和分析
  - 图像中二维码检测
  - 图像分析和处理
  - 广告文本检测和删除
- **二维码消毒**：从 EPUB 图像中删除或模糊二维码
- **广告文本删除**：从 EPUB 内容中删除广告文本模式
- **灵活配置**：可定制的模式和扫描选项

### 安全检查

该工具执行全面的安全分析，包括：

- **可疑代码模式**：检测 eval()、exec()、system() 调用和其他危险函数
- **广告检测**：识别常见广告模式和促销内容
- **恶意软件指标**：扫描可执行文件、脚本和其他潜在有害内容
- **脚本分析**：检测嵌入的 JavaScript 和其他脚本语言
- **加密模式**：识别潜在危险上下文中的加密算法
- **文件完整性**：检查存档中的重复文件和可疑文件扩展名

### 安装

#### 前置要求

- Rust（最新稳定版本）
- Cargo 包管理器

#### 从源码构建

```bash
# 克隆仓库
git clone <repository-url>
cd check_txt

# 构建项目
cargo build --release

# 二进制文件将位于 target/release/check_txt
```

#### Docker（可选）

```bash
# 构建 Docker 镜像
docker build -t check_txt .

# 使用 Docker Compose 运行
docker-compose up
```

### 配置

#### 环境变量

在项目根目录创建 `.env` 文件：

```env
# 病毒扫描必需
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

#### VirusTotal API 密钥

要启用病毒扫描功能：

1. 在 [VirusTotal](https://www.virustotal.com/) 注册
2. 从账户设置中获取 API 密钥
3. 将其添加到 `.env` 文件中

### 使用方法

#### 命令行界面

```bash
# 检查单个文件
check_txt --path /path/to/file.txt --file-type txt

# 检查目录中的文件
check_txt --path /path/to/directory --file-type txt

# 启用深度扫描
check_txt --path /path/to/file.epub --file-type epub --deep-scan

# 启用病毒扫描
check_txt --path /path/to/file.txt --file-type txt --virus-scan

# 设置自定义文件大小限制（MB）
check_txt --path /path/to/file.txt --file-type txt --max-size 50

# 启动 Web 服务器
check_txt --web
```

#### Web 界面

1. 启动 Web 服务器：
   ```bash
   check_txt --web
   ```

2. 打开浏览器并导航到 `http://127.0.0.1:8090`

3. 通过 Web 界面上传文件进行分析

### 命令行选项

| 选项 | 简写 | 描述 | 默认值 |
|------|------|------|--------|
| `--path` | `-p` | 要检查的文件或目录路径 | 必需 |
| `--file-type` | `-f` | 要检查的文件类型（txt, epub） | 必需 |
| `--max-size` | `-m` | 最大文件大小（MB） | 100 |
| `--deep-scan` | `-d` | 启用深度扫描 | false |
| `--virus-scan` | `-v` | 启用病毒扫描 | false |
| `--web` | `-w` | 启动 Web 服务器 | false |

### 使用示例

#### 基本文件检查
```bash
check_txt --path document.txt --file-type txt
```

#### 全面 EPUB 分析
```bash
check_txt --path book.epub --file-type epub --deep-scan --virus-scan --max-size 200
```

#### 目录扫描
```bash
check_txt --path ./documents --file-type txt --deep-scan
```

### 输出示例

#### 安全文件
```
✅ File appears to be secure!
```

#### 有问题的文件
```
⚠️ Found potential security issues:
- Suspicious code pattern found: (?i)(eval\s*\()
- Advertisement pattern found: (?i)(click here)
- Potential malware pattern found: (?i)(\.exe)
```

### 项目结构

```