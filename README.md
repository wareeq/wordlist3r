# wordlist3r 🎯

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/release/wareeqshile/wordlist3r.svg)](https://github.com/wareeqshile/wordlist3r/releases/)
[![Website](https://img.shields.io/badge/website-wareeqshile.com-blue)](https://www.wareeqshile.com)
[![Twitter Follow](https://img.shields.io/twitter/follow/wareeq_shile?style=social)](https://twitter.com/wareeq_shile)

**Fast and intelligent wordlist generator for directory fuzzing.**

wordlist3r is a powerful Python tool that extracts custom wordlists from live web applications by analyzing page content, titles, metadata, and domain structures. Perfect for bug bounty hunters and penetration testers who need targeted wordlists for directory brute-forcing.

## 🚀 Features

- **Multi-source extraction**: Domains, subdomains, page titles, content, metadata
- **Smart filtering**: Automatic IP address filtering, common word removal
- **Concurrent processing**: Fast async HTTP requests with rate limiting  
- **SSL-friendly**: Handles self-signed certificates and SSL errors
- **Flexible input**: Supports wildcards, multiple files, direct URLs
- **Pentesting optimized**: Built for reconnaissance workflows
- **Clean output**: Removes noise and focuses on meaningful directory names

## 📦 Installation

### Prerequisites
- Python 3.7+
- pip

### Install from Source
```bash
git clone https://github.com/wareeqshile/wordlist3r.git
cd wordlist3r
pip install -r requirements.txt

# Install as package (recommended)
pip install -e .

# Or run directly without installation
python wordlist3r/main.py --help
```

### Quick Install (One-liner)
```bash
git clone https://github.com/wareeq/wordlist3r.git && cd wordlist3r && pip install -e . --break-system-packages
```

## 🎯 Quick Start

```bash
# After installation, use wordlist3r command:

# Extract from URLs in a file
wordlist3r -f alive_urls.txt -o custom_wordlist.txt

# Process multiple reconnaissance files  
wordlist3r -f ~/recon/*/alive.txt -o combined_wordlist.txt

# Single URL with verbose output
wordlist3r -u https://example.com -o wordlist.txt -v

# Multiple URLs directly
wordlist3r https://site1.com https://site2.com -o wordlist.txt

# Custom filtering options
wordlist3r -f urls.txt --min-length 4 --min-freq 3 --sort -o filtered.txt
```

### Alternative: Run without installation
```bash
# If you prefer not to install as package:
python wordlist3r/main.py -f alive_urls.txt -o custom_wordlist.txt
```

## 📋 Usage

```
wordlist3r [-h] [-f FILE] [-u URL] [--files FILES [FILES ...]] 
           [-o OUTPUT] [--sort] [--min-length N] [--max-length N] 
           [--min-freq N] [--no-ip-filter] [-v] [urls ...]

Extract custom wordlists from URLs for directory fuzzing

positional arguments:
  urls                  URLs to process directly

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File(s) containing URLs (supports wildcards)
  -u URL, --url URL     Single URL to add (can be used multiple times)
  --files FILES [FILES ...]
                        Multiple specific files containing URLs
  -o OUTPUT, --output OUTPUT
                        Output wordlist file
  --sort                Sort output wordlist
  --min-length N        Minimum word length (default: 3)
  --max-length N        Maximum word length (default: 50)
  --min-freq N          Minimum word frequency (default: 2)
  --no-ip-filter        Disable automatic IP address filtering
  -v, --verbose         Enable verbose output
```

## 💡 Examples

### Basic Usage
```bash
# Process a single file
wordlist3r -f subdomains.txt -o wordlist.txt

# Multiple files with wildcards (great for recon!)
wordlist3r -f ~/recon/*/alive.txt -o mega_wordlist.txt

# Add individual URLs
wordlist3r -u https://app.target.com -u https://admin.target.com -o wordlist.txt
```

### Advanced Filtering
```bash
# Longer words only, higher frequency threshold
wordlist3r -f urls.txt --min-length 5 --min-freq 3 -o quality_words.txt

# Keep IP addresses (useful for certain scenarios)
wordlist3r -f urls.txt --no-ip-filter -o wordlist_with_ips.txt

# Sorted output for easy analysis
wordlist3r -f urls.txt --sort -o sorted_wordlist.txt
```

## 🔍 What It Extracts

### Domain & Subdomain Parts
- `admin.example.com` → `admin`, `example`
- `api-v2.staging.corp.com` → `api`, `v2`, `staging`, `corp`

### Page Titles
- "Admin Dashboard - Company Portal" → `admin`, `dashboard`, `company`, `portal`

### Meta Tags & Attributes
- Keywords, descriptions, alt text, title attributes
- OpenGraph and Twitter card metadata

### Content Analysis  
- Frequently occurring words (configurable threshold)
- Link text and URL paths
- Form field names and IDs

### Smart Filtering
- ✅ Removes IP addresses and octets
- ✅ Filters common English words
- ✅ Eliminates HTML/web noise terms
- ✅ Focuses on directory-relevant terms


## 🎛️ Configuration

### Performance Tuning
- Concurrent connections: 100 total, 20 per host
- Request timeout: 15 seconds  
- SSL verification: Disabled (pentesting mode)
- Batch processing: 50 URLs per batch

### Word Filtering
- Default min length: 3 characters
- Default max length: 50 characters  
- Default min frequency: 2 occurrences
- IP filtering: Enabled by default

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Setup
```bash
git clone https://github.com/wareeq/wordlist3r.git
cd wordlist3r
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
```

### Connect with the Author
- 🌐 **Website**: [wareeqshile.com](https://www.wareeqshile.com)
- 🐦 **Twitter**: [@wareeq_shile](https://twitter.com/wareeq_shile) 

Feel free to reach out for questions, suggestions, or collaboration!

## 🐛 Bug Reports & Issues

Found a bug or have a feature request? Please open an issue with:

- Your Python version (`python --version`)
- Operating system 
- Complete error message/traceback
- Steps to reproduce
- Example URLs (if safe to share)

**Installation Issues?**
- Make sure you have Python 3.7+
- Try `pip install -e . --user` if you get permission errors
- Use `python wordlist3r/main.py` if package installation fails

## 📝 Changelog

### v1.0.0 (2024)
- Initial release
- Multi-source word extraction
- Async HTTP processing
- Smart filtering system
- Wildcard file support

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Happy Hunting! 🎯**

*Made with ❤️ for the cybersecurity community*
