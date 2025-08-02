# JWT Security Analyzer

A comprehensive desktop application for JWT token analysis, security testing, and penetration testing. Built with Electron for cross-platform compatibility and designed for security professionals and developers.

## Features

### Core JWT Tools
- **JWT Decoder** - Decode and analyze JWT tokens to view structure, claims, and metadata
- **JWT Encoder** - Create custom JWT tokens with configurable headers, payloads, and signatures
- **Token Validator** - Verify JWT signatures and validate claims against provided secrets/keys
- **Key Generator** - Generate cryptographically secure HMAC secrets and RSA key pairs

### Security Analysis
- **Comprehensive Scanner** - Automated vulnerability detection with security scoring
- **16+ Attack Vectors** - Generate attack payloads for common JWT vulnerabilities
- **Brute Force Testing** - Dictionary-based attacks against weak HMAC secrets
- **Modern Vulnerability Detection** - Including JWK injection, algorithm confusion, and more

### Network & Testing Tools
- **Network Proxy** - Intercept HTTP/HTTPS traffic to capture JWT tokens from live requests
- **HTTPS Interception** - Full SSL/TLS decryption with CA certificate support
- **Replay Attack Simulator** - Test tokens for replay vulnerabilities
- **Token Comparison** - Compare JWT tokens side-by-side to identify differences

### Advanced Testing Tools
- **HTTP Request Tester** - Test JWT tokens in real HTTP requests with custom headers
- **Base64 Encoder/Decoder** - Essential utility for JWT component manipulation
- **Claims Analysis** - Detailed breakdown of standard and custom JWT claims
- **Algorithm Support** - Full support for HMAC, RSA, and none algorithms

### User Experience
- **Multi-Language Support** - Available in English and German
- **Modern Interface** - Clean, intuitive design with dark theme
- **Auto-Updates** - Automatic update checking and installation
- **Comprehensive Help** - Built-in documentation and usage guides
- **Cross-Platform** - Windows, macOS, and Linux support

## Supported Algorithms

### HMAC Algorithms (Symmetric)
- **HS256** - HMAC using SHA-256
- **HS384** - HMAC using SHA-384
- **HS512** - HMAC using SHA-512

### RSA Algorithms (Asymmetric)
- **RS256** - RSA using SHA-256
- **RS384** - RSA using SHA-384
- **RS512** - RSA using SHA-512

### Special Cases
- **none** - No signature verification (dangerous but testable)

## Attack Vectors

### Critical Vulnerabilities
- **Algorithm None Attack** - Bypass signature verification by setting algorithm to "none"
- **JWK Injection** - Inject malicious JSON Web Keys in token headers
- **Kid Parameter Injection** - Path traversal and command injection via "kid" parameter

### High-Risk Attacks
- **Algorithm Confusion** - Change RS256 to HS256 using public key as HMAC secret
- **JKU URL Hijacking** - Point JKU to attacker-controlled JWK sets
- **X5U Certificate Exploit** - Exploit X.509 certificate URL parameters
- **JWT Smuggling** - Exploit parsing differences between JWT libraries
- **JWKS Cache Poisoning** - Poison JWKS cache with malicious keys

### Medium-Risk Attacks
- **Weak Secret Detection** - Test against common passwords and weak secrets
- **Nested JWT Attack** - JWT-in-JWT confusion and privilege escalation
- **Audience Confusion** - Multi-audience token reuse across services
- **Parameter Pollution** - Duplicate parameters with conflicting values
- **JWT Sidejacking** - Session hijacking specific to JWT implementations

### Specialized Attacks
- **Token Replay** - Remove time-based claims for token reuse
- **Timing Attack** - Exploit timing differences in signature verification
- **Quantum-Prep Analysis** - Assess quantum computing vulnerability

## Network Proxy Features

### HTTP/HTTPS Interception
- **Live Traffic Capture** - Intercept JWT tokens from network requests
- **SSL/TLS Decryption** - Full HTTPS traffic inspection with MITM capabilities
- **CA Certificate Export** - Export and install trusted root certificate
- **Real-Time Token Detection** - Automatic JWT extraction from headers, cookies, and bodies

### Proxy Configuration
1. **Enable HTTPS Interception** - Check the option in proxy settings
2. **Export CA Certificate** - Click "Export CA Certificate" button
3. **Install Certificate** - Add to browser's trusted certificate store
4. **Configure Browser** - Set proxy to 127.0.0.1:8080 (default port)
5. **Start Capturing** - All JWT tokens will be automatically captured

### Token Replay Testing
- **Automated Replay** - Send multiple requests with captured tokens
- **Configurable Parameters** - Adjust delay, request count, and HTTP method
- **Result Analysis** - Monitor response codes and timing
- **Vulnerability Detection** - Identify tokens vulnerable to replay attacks

### Token Comparison Tool
- **Side-by-Side Analysis** - Compare two JWT tokens visually
- **Difference Highlighting** - Identify changes in headers, claims, and signatures
- **Structural Comparison** - Detect algorithm changes and claim modifications
- **Security Impact** - Understand how token changes affect security

## Quick Start

### Basic Token Analysis
1. **Decode Tokens** - Paste any JWT in the Decoder tab to see its structure
2. **Analyze Security** - Use Security Analysis to identify vulnerabilities
3. **Generate Attacks** - Create attack payloads in the Attack Vectors tab
4. **Validate Tokens** - Verify signatures using the Token Validator

### Network Traffic Analysis
1. **Start Proxy** - Enable proxy with optional HTTPS interception
2. **Configure Browser** - Point browser proxy settings to localhost:8080
3. **Browse Target Site** - Navigate to pages using JWT authentication
4. **Capture Tokens** - View all captured JWT tokens in real-time
5. **Analyze & Test** - Use captured tokens for security analysis

### Penetration Testing Workflow
1. **Gather JWT Tokens** - Use proxy or paste from target application
2. **Run Security Scan** - Comprehensive vulnerability analysis with scoring
3. **Generate Attack Payloads** - Create targeted exploits based on findings
4. **Test with HTTP Tester** - Validate attacks against live endpoints
5. **Simulate Replay Attacks** - Test token replay vulnerabilities

## Security Analysis Features

### Vulnerability Detection
- **Algorithm Security** - Weak or dangerous algorithms
- **Claims Validation** - Missing or insecure claims
- **Signature Analysis** - Signature strength and entropy
- **Token Structure** - Malformed or oversized tokens
- **Modern Attacks** - JWK injection, kid exploitation, etc.
- **Best Practices** - RFC compliance and security standards

### Security Scoring
- **100-Point Scale** - Comprehensive security assessment
- **Severity Classification** - Critical, High, Medium, Low rankings
- **Detailed Recommendations** - Specific remediation guidance
- **Impact Analysis** - Real-world attack scenarios

## Installation & Setup

1. **Download** - Get the latest release for your platform
2. **Install** - Run the installer (Windows) or mount DMG (macOS)
3. **Launch** - Start JWT Security Analyzer
4. **Auto-Update** - App will check for updates automatically

### HTTPS Proxy Setup (Optional)
1. **Export CA Certificate** - From proxy settings
2. **Install in Browser** - Add to trusted certificate authorities
3. **Configure Proxy** - Set browser proxy to 127.0.0.1:8080
4. **Enable HTTPS Interception** - Check the option before starting proxy

## Security Disclaimer

⚠️ **Important**: This tool is designed for legitimate security testing and educational purposes only.

- Always ensure you have proper authorization before testing any system
- Users are responsible for complying with applicable laws and regulations
- Only test systems you own or have explicit permission to test
- Use responsibly and ethically in accordance with your organization's policies

## Technical Details

- **Framework** - Electron for cross-platform desktop apps
- **JWT Processing** - jsonwebtoken library with comprehensive algorithm support
- **Cryptography** - Node.js crypto module and node-forge for RSA/certificate operations
- **Proxy Engine** - HTTP-proxy with custom SSL/TLS interception
- **UI Technology** - Modern HTML5, CSS3, and JavaScript
- **Supported Platforms** - Windows 10+, macOS 10.14+, Linux (Ubuntu 18.04+)

## Update History

**02/08/2025** - 1.1.0 - Added Network Proxy with HTTP/HTTPS interception
- Implemented SSL/TLS decryption with CA certificate generation
- Added JWT token capture from live network traffic
- Introduced Replay Attack Simulator
- Added Token Comparison tool for side-by-side analysis
- Improved navigation with collapsible sections
- Enhanced security analysis with network attack vectors
- Updated help documentation with new features
- Fixed various UI/UX improvements

**25/07/2025** - 1.0.0 - Initial Release
- Complete JWT security testing suite
- 16+ attack vector generators
- Multi-language support (English/German)
- Comprehensive security analysis engine
- Modern responsive interface
- Auto-updater functionality
- Built-in help documentation

## Use Cases

### Developers
- **API Security Testing** - Test JWT implementations before deployment
- **Token Debugging** - Decode and analyze problematic tokens
- **Key Management** - Generate secure keys for development
- **Security Education** - Learn JWT vulnerabilities hands-on

### Security Researchers
- **Live Traffic Analysis** - Capture and analyze JWT tokens from applications
- **Vulnerability Research** - Explore new JWT attack vectors
- **Replay Testing** - Identify replay-vulnerable implementations
- **Security Audits** - Comprehensive JWT security assessments

### Penetration Testers
- **Network Interception** - MITM proxy for JWT token extraction
- **Attack Generation** - Create exploit payloads for discovered vulnerabilities
- **Token Manipulation** - Modify and test token variations
- **Automated Testing** - Bulk security analysis of captured tokens

## Credits

Developed by **www.bavamont.com**

**Built for**: Security professionals, penetration testers, and developers

**Powered by**:
- Electron framework
- jsonwebtoken library
- Node.js cryptography
- node-forge for certificate operations
- http-proxy for network interception