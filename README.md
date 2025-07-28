# JWT Security Analyzer

A desktop application for JWT token analysis, security testing, and penetration testing. Built with Electron for cross-platform compatibility and designed for developers.

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

## Quick Start

### Basic Token Analysis
1. **Decode Tokens** - Paste any JWT in the Decoder tab to see its structure
2. **Analyze Security** - Use Security Analysis to identify vulnerabilities
3. **Generate Attacks** - Create attack payloads in the Attack Vectors tab
4. **Validate Tokens** - Verify signatures using the Token Validator

### Penetration Testing Workflow
1. **Gather JWT Tokens** - From target application or provided samples
2. **Run Security Scan** - Comprehensive vulnerability analysis with scoring
3. **Generate Attack Payloads** - Create targeted exploits based on findings
4. **Test with HTTP Tester** - Validate attacks against live endpoints

## Interface Overview

### Main Navigation
- **JWT Decoder** - Token structure analysis and claims inspection
- **JWT Encoder** - Custom token creation with templates
- **Security Analysis** - Automated vulnerability scanning
- **Attack Vectors** - 16+ attack payload generators
- **Brute Force** - Dictionary attacks against HMAC secrets
- **Key Generator** - Secure key generation for testing
- **Token Validator** - Signature verification and claims validation

### Utilities Section
- **HTTP Tester** - Test tokens in real HTTP requests
- **Base64 Tools** - Encode/decode utilities
- **Help** - Comprehensive documentation

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

## Advanced Features

### Brute Force Testing
- **Dictionary Attacks** - Test against common password lists
- **Custom Wordlists** - Load your own secret dictionaries
- **Real-Time Progress** - Live statistics and speed monitoring
- **Common Secrets** - Built-in database of weak secrets

### Key Generation
- **HMAC Secrets** - 256, 384, and 512-bit secure random secrets
- **RSA Key Pairs** - 2048, 3072, and 4096-bit key generation
- **Production Ready** - Cryptographically secure random generation
- **Multiple Formats** - PEM format support for RSA keys

### HTTP Testing
- **Method Support** - GET, POST, PUT, DELETE, PATCH
- **Custom Headers** - Full header customization
- **Bearer Token Auth** - Standard JWT authorization
- **Response Analysis** - Status codes, headers, and timing

## Installation & Setup

1. **Download** - Get the latest release for your platform
2. **Install** - Run the installer (Windows) or mount DMG (macOS)
3. **Launch** - Start JWT Security Analyzer
4. **Auto-Update** - App will check for updates automatically

## Security Disclaimer

⚠️ **Important**: This tool is designed for legitimate security testing and educational purposes only.

- Always ensure you have proper authorization before testing any system
- Users are responsible for complying with applicable laws and regulations
- Only test systems you own or have explicit permission to test
- Use responsibly and ethically in accordance with your organization's policies

## Technical Details

- **Framework** - Electron for cross-platform desktop apps
- **JWT Processing** - jsonwebtoken library with comprehensive algorithm support
- **Cryptography** - Node.js crypto module and forge.js for RSA operations
- **UI Technology** - Modern HTML5, CSS3, and JavaScript
- **Supported Platforms** - Windows 10+, macOS 10.14+, Linux (Ubuntu 18.04+)

## Update History

**1.0.0** - Initial Release
- Complete JWT security testing suite
- 16+ attack vector generators
- Multi-language support (English/German)
- Comprehensive security analysis engine
- Modern responsive interface
- Auto-updater functionality
- Built-in help documentation

## Use Cases

### Developers
- **Security Testing** - Test JWT implementations before deployment
- **Learning Tool** - Understand JWT vulnerabilities and best practices
- **Debugging** - Decode and analyze problematic tokens
- **Key Management** - Generate secure keys for development

### Security Researchers
- **Vulnerability Research** - Explore new JWT attack vectors
- **Algorithm Analysis** - Test different signing algorithms
- **Parser Testing** - Test JWT library implementations
- **Educational Content** - Demonstrate JWT security concepts

## Credits

**Developed by**: www.bavamont.com

**Built for**: Penetration testers and developers

**Powered by**:
- Electron framework
- jsonwebtoken library
- Node.js cryptography
- forge.js for RSA operations