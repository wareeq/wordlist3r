#!/usr/bin/env python3
"""
Fast URL Wordlist Extractor for Directory Fuzzing
Extracts custom wordlists from URLs including:
- Title words
- Subdomain names  
- Domain names
- Unique repeated words from page content
- Intelligent IP address filtering
"""

import asyncio
import aiohttp
import argparse
import re
import sys
import glob
import ssl
import os
from urllib.parse import urlparse
from collections import Counter
from bs4 import BeautifulSoup
import tldextract
from typing import Set, List
import time
import ipaddress

class WordlistExtractor:
    def __init__(self, min_word_length=3, max_word_length=50, min_frequency=2, filter_ips=True, verbose=False):
        self.min_word_length = min_word_length
        self.max_word_length = max_word_length
        self.min_frequency = min_frequency
        self.filter_ips = filter_ips
        self.verbose = verbose
        self.session = None
        
        # IP detection patterns
        self.full_ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        self.ipv6_pattern = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')
        
        # Common words to filter out
        self.common_words = {
            'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 
            'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 
            'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy',
            'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use', 'www', 'com',
            'org', 'net', 'html', 'htm', 'php', 'jsp', 'asp', 'aspx', 'http', 'https',
            'home', 'page', 'site', 'web', 'about', 'contact', 'login', 'register',
            'search', 'more', 'view', 'click', 'here', 'read', 'information', 'service'
        }

    async def __aenter__(self):
        # Create permissive SSL context for pentesting
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        timeout = aiohttp.ClientTimeout(total=15, connect=8)
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            ssl=ssl_context,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def is_ip_related(self, word: str) -> bool:
        """Enhanced IP detection"""
        if not self.filter_ips:
            return False
        
        # Check for complete IPv4 addresses
        if self.full_ip_pattern.match(word):
            try:
                ipaddress.IPv4Address(word)
                return True
            except ValueError:
                pass
        
        # Check for IPv6 addresses
        if self.ipv6_pattern.match(word):
            try:
                ipaddress.IPv6Address(word)
                return True
            except ValueError:
                pass
        
        # Check for IP octets (0-255)
        if word.isdigit():
            num = int(word)
            if 0 <= num <= 255:
                return True
        
        # Common IP-related terms
        ip_terms = {'localhost', 'loopback', 'router', 'gateway'}
        if word.lower() in ip_terms:
            return True
            
        return False

    def is_valid_word(self, word: str) -> bool:
        """Check if word meets filtering criteria"""
        if not word or len(word) < self.min_word_length or len(word) > self.max_word_length:
            return False
        
        word_lower = word.lower()
        
        # Filter common words
        if word_lower in self.common_words:
            return False
            
        # Filter IP-related terms
        if self.is_ip_related(word):
            return False
        
        # Must contain at least one letter
        if not re.search(r'[a-zA-Z]', word):
            return False
            
        # Filter pure numeric strings (but allow alphanumeric)
        if word.isdigit():
            return False
            
        return True

    def extract_domain_words(self, url: str) -> Set[str]:
        """Extract words from domain and subdomains"""
        words = set()
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            
            # Skip if hostname is an IP address
            if self.full_ip_pattern.match(hostname):
                return words
            
            # Use tldextract for better domain parsing
            ext = tldextract.extract(url)
            
            # Add domain parts
            for part in [ext.subdomain, ext.domain]:
                if part:
                    # Split on dots and hyphens
                    subparts = re.split(r'[.-]', part)
                    for subpart in subparts:
                        if subpart and self.is_valid_word(subpart):
                            words.add(subpart.lower())
            
            # Add suffix if not common TLD
            if ext.suffix and ext.suffix not in ['com', 'org', 'net', 'edu', 'gov', 'mil']:
                if self.is_valid_word(ext.suffix):
                    words.add(ext.suffix.lower())
                    
        except Exception as e:
            if self.verbose:
                print(f"Error parsing domain from {url}: {e}")
        
        return words

    def extract_title_words(self, soup: BeautifulSoup) -> Set[str]:
        """Extract words from page title"""
        words = set()
        
        title_tag = soup.find('title')
        if title_tag:
            title = title_tag.get_text().strip()
            if title:
                # Extract words (letters and numbers)
                title_words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9]*\b', title)
                for word in title_words:
                    if self.is_valid_word(word):
                        words.add(word.lower())
        
        return words

    def extract_content_words(self, soup: BeautifulSoup) -> Set[str]:
        """Extract frequently occurring words from page content"""
        words = set()
        
        # Remove script, style, and other non-content elements
        for element in soup(['script', 'style', 'meta', 'link', 'noscript']):
            element.decompose()
        
        # Get text content
        text = soup.get_text(separator=' ', strip=True)
        
        if not text:
            return words
        
        # Extract words (must start with letter, can contain numbers)
        all_words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9]*\b', text.lower())
        
        # Count word frequency
        word_counts = Counter(all_words)
        
        # Add words that appear frequently enough
        for word, count in word_counts.items():
            if count >= self.min_frequency and self.is_valid_word(word):
                words.add(word)
        
        return words

    def extract_metadata_words(self, soup: BeautifulSoup) -> Set[str]:
        """Extract words from meta tags, alt attributes, etc."""
        words = set()
        
        # Meta tags
        for meta in soup.find_all('meta'):
            for attr in ['content', 'name', 'property']:
                value = meta.get(attr, '')
                if value:
                    meta_words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9]*\b', value.lower())
                    for word in meta_words:
                        if self.is_valid_word(word):
                            words.add(word)
        
        # Alt and title attributes
        for tag in soup.find_all(['img', 'area', 'input', 'a']):
            for attr in ['alt', 'title']:
                value = tag.get(attr, '')
                if value:
                    attr_words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9]*\b', value.lower())
                    for word in attr_words:
                        if self.is_valid_word(word):
                            words.add(word)
        
        # Extract from URLs in href and src attributes
        for tag in soup.find_all(['a', 'img', 'link', 'script']):
            for attr in ['href', 'src']:
                url = tag.get(attr, '')
                if url:
                    # Extract path components
                    path_words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9]*\b', url.lower())
                    for word in path_words:
                        if self.is_valid_word(word) and len(word) >= 4:  # Longer words from URLs
                            words.add(word)
        
        return words

    async def fetch_and_extract(self, url: str) -> Set[str]:
        """Fetch URL and extract all words"""
        words = set()
        
        try:
            # Add domain/subdomain words
            words.update(self.extract_domain_words(url))
            
            # Try both HTTP and HTTPS
            urls_to_try = [url]
            if url.startswith('https://'):
                urls_to_try.append(url.replace('https://', 'http://'))
            elif url.startswith('http://'):
                urls_to_try.append(url.replace('http://', 'https://'))
            
            content = None
            successful_url = None
            
            for try_url in urls_to_try:
                try:
                    async with self.session.get(try_url) as response:
                        if 200 <= response.status < 400:
                            content = await response.text(errors='ignore')
                            successful_url = try_url
                            break
                        elif response.status == 403:
                            if self.verbose:
                                print(f"HTTP {response.status} (Forbidden) for {try_url}")
                        elif response.status >= 400:
                            if self.verbose:
                                print(f"HTTP {response.status} for {try_url}")
                except Exception as e:
                    if self.verbose and try_url == urls_to_try[-1]:  # Only print error for last attempt
                        print(f"Connection error for {try_url}: {str(e)[:100]}...")
                    continue
            
            if content:
                try:
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Extract words from various sources
                    words.update(self.extract_title_words(soup))
                    words.update(self.extract_content_words(soup))
                    words.update(self.extract_metadata_words(soup))
                    
                    if self.verbose:
                        print(f"✓ Extracted {len(words)} words from {successful_url}")
                        
                except Exception as e:
                    if self.verbose:
                        print(f"Error parsing HTML from {url}: {e}")
            else:
                if self.verbose:
                    print(f"✗ Could not fetch content from {url}")
                    
        except Exception as e:
            if self.verbose:
                print(f"Unexpected error processing {url}: {e}")
        
        return words

    async def process_urls(self, urls: List[str]) -> Set[str]:
        """Process multiple URLs concurrently with batching"""
        print(f"Processing {len(urls)} URLs...")
        
        all_words = set()
        batch_size = 50  # Process in smaller batches to avoid overwhelming servers
        
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i+batch_size]
            batch_start = i + 1
            batch_end = min(i + batch_size, len(urls))
            
            if self.verbose:
                print(f"\nProcessing batch {batch_start}-{batch_end}...")
            
            # Create tasks for current batch
            tasks = [self.fetch_and_extract(url) for url in batch]
            
            # Process batch with progress indication
            completed = 0
            for task in asyncio.as_completed(tasks):
                words = await task
                all_words.update(words)
                completed += 1
                
                if not self.verbose:
                    progress = batch_start + completed - 1
                    print(f"Completed {progress}/{len(urls)} URLs", end='\r')
            
            # Small delay between batches
            if i + batch_size < len(urls):
                await asyncio.sleep(1)
        
        print()  # New line after progress
        return all_words

def find_files_after_flag(flag: str) -> List[str]:
    """Find all arguments after a flag until next flag or end"""
    try:
        flag_index = sys.argv.index(flag)
        files = []
        for i in range(flag_index + 1, len(sys.argv)):
            arg = sys.argv[i]
            if arg.startswith('-'):  # Next flag
                break
            files.append(arg)
        return files
    except ValueError:
        return []

def expand_file_patterns(patterns: List[str]) -> List[str]:
    """Expand file patterns and resolve paths"""
    all_files = []
    
    for pattern in patterns:
        # Handle tilde expansion
        expanded = os.path.expanduser(pattern)
        
        # If it's an existing file, add it directly
        if os.path.exists(expanded) and os.path.isfile(expanded):
            all_files.append(expanded)
        # Handle glob patterns
        elif '*' in expanded or '?' in expanded:
            matching_files = glob.glob(expanded)
            if matching_files:
                all_files.extend(sorted(matching_files))
            else:
                print(f"Warning: No files found matching pattern '{pattern}'")
        else:
            print(f"Warning: File not found '{pattern}'")
    
    return all_files

def load_urls_from_files(file_paths: List[str]) -> List[str]:
    """Load URLs from files"""
    all_urls = []
    
    if not file_paths:
        return all_urls
    
    print(f"Loading URLs from {len(file_paths)} file(s):")
    
    for file_path in file_paths:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_urls = []
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        file_urls.append(line)
                
                all_urls.extend(file_urls)
                print(f"  {os.path.basename(file_path)}: {len(file_urls)} URLs")
                
        except Exception as e:
            print(f"  Error reading '{file_path}': {e}")
    
    return all_urls

def validate_and_clean_url(url: str) -> str:
    """Validate and normalize URL"""
    url = url.strip()
    
    # Skip empty or invalid URLs
    if not url or url.startswith('#'):
        return None
    
    # Handle different URL formats
    if url.startswith('http://') or url.startswith('https://'):
        return url
    elif url.startswith('//'):
        return 'https:' + url
    elif ':' in url and not url.startswith('/'):
        # Likely has protocol
        return url
    else:
        # Assume hostname/domain
        return 'https://' + url

def main():
    parser = argparse.ArgumentParser(
        description='Extract custom wordlists from URLs for directory fuzzing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f urls.txt -o wordlist.txt
  %(prog)s -f ~/recondata/*/alive.txt -o custom.txt --sort  
  %(prog)s --files file1.txt file2.txt file3.txt -o combined.txt
  %(prog)s https://example.com https://target.com
  %(prog)s -u https://site1.com -u https://site2.com -o wordlist.txt
  %(prog)s -f "~/recon/*/alive.txt" --min-length 4 --verbose
        """
    )
    
    # Input sources
    parser.add_argument('urls', nargs='*', help='URLs to process directly')
    parser.add_argument('-f', '--file', help='File(s) containing URLs (supports wildcards like ~/recon/*/alive.txt)')
    parser.add_argument('-u', '--url', action='append', help='Single URL to add (can be used multiple times)')
    parser.add_argument('--files', nargs='+', help='Multiple specific files containing URLs')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output wordlist file')
    parser.add_argument('--sort', action='store_true', help='Sort output wordlist')
    
    # Filtering options
    parser.add_argument('--min-length', type=int, default=3, 
                       help='Minimum word length (default: 3)')
    parser.add_argument('--max-length', type=int, default=50,
                       help='Maximum word length (default: 50)')
    parser.add_argument('--min-freq', type=int, default=2,
                       help='Minimum word frequency (default: 2)')
    parser.add_argument('--no-ip-filter', action='store_true',
                       help='Disable automatic IP address filtering')
    
    # Debugging
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Collect URLs from all sources
    urls = []
    
    # From command line arguments (direct URLs)
    if args.urls:
        print(f"Adding {len(args.urls)} URLs from command line")
        urls.extend(args.urls)
    
    # From single -u/--url arguments
    if args.url:
        print(f"Adding {len(args.url)} URLs from -u flags")
        urls.extend(args.url)
    
    # From -f/--file (supports wildcards, handles shell expansion)
    if args.file:
        # Handle shell expansion - check if shell expanded the wildcard
        file_patterns = find_files_after_flag('-f') or find_files_after_flag('--file')
        
        if not file_patterns:
            # No shell expansion, use the argument as is
            file_patterns = [args.file]
        
        # Expand patterns and load URLs
        file_paths = expand_file_patterns(file_patterns)
        if file_paths:
            file_urls = load_urls_from_files(file_paths)
            urls.extend(file_urls)
    
    # From --files (multiple specific files)
    if args.files:
        file_paths = expand_file_patterns(args.files)
        if file_paths:
            file_urls = load_urls_from_files(file_paths)
            urls.extend(file_urls)
    
    if not urls:
        parser.print_help()
        print("\nError: No URLs provided.")
        return 1
    
    print(f"\nTotal raw URLs loaded: {len(urls)}")
    
    # Clean and deduplicate URLs
    clean_urls = []
    seen = set()
    invalid_count = 0
    
    for i, url in enumerate(urls):
        try:
            clean_url = validate_and_clean_url(url)
            if clean_url and clean_url not in seen:
                clean_urls.append(clean_url)
                seen.add(clean_url)
        except Exception as e:
            invalid_count += 1
            if args.verbose:
                print(f"Skipping invalid URL '{url}': {e}")
    
    if not clean_urls:
        print("Error: No valid URLs found after cleaning.")
        return 1
    
    print(f"Valid unique URLs: {len(clean_urls)}")
    if invalid_count > 0:
        print(f"Skipped invalid URLs: {invalid_count}")
    
    if args.verbose:
        print("\nFirst 10 URLs to process:")
        for i, url in enumerate(clean_urls[:10]):
            print(f"  {i+1:2d}. {url}")
        if len(clean_urls) > 10:
            print(f"      ... and {len(clean_urls) - 10} more URLs")
    
    async def run_extraction():
        start_time = time.time()
        
        async with WordlistExtractor(
            min_word_length=args.min_length,
            max_word_length=args.max_length,
            min_frequency=args.min_freq,
            filter_ips=not args.no_ip_filter,
            verbose=args.verbose
        ) as extractor:
            
            wordlist = await extractor.process_urls(clean_urls)
            
            if not wordlist:
                print("Warning: No words extracted!")
                return 1
            
            # Convert to sorted list if requested
            final_wordlist = sorted(list(wordlist)) if args.sort else list(wordlist)
            
            # Output results
            if args.output:
                try:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        for word in final_wordlist:
                            f.write(f"{word}\n")
                    print(f"Wordlist saved to {args.output}")
                except Exception as e:
                    print(f"Error saving wordlist: {e}")
                    return 1
            else:
                for word in final_wordlist:
                    print(word)
            
            elapsed = time.time() - start_time
            print(f"\n✓ Extracted {len(final_wordlist)} unique words from {len(clean_urls)} URLs in {elapsed:.2f}s")
            
            if args.verbose:
                print(f"Average: {len(final_wordlist)/len(clean_urls):.1f} words per URL")
    
    try:
        return asyncio.run(run_extraction()) or 0
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())