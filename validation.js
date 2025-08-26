/**
 * Input validation utilities for secure JWT processing
 * Provides static methods for validating JWT tokens, URLs, file paths, and headers
 * @class
 */
class ValidationUtils {
    /**
     * Validates JWT token format and base64url encoding
     * @static
     * @param {string} token - The JWT token to validate
     * @returns {boolean} True if token has valid JWT format
     */
    static isValidJWT(token) {
        if (!token || typeof token !== 'string') return false;
        
        const parts = token.split('.');
        if (parts.length !== 3) return false;
        
        try {
            parts.forEach(part => {
                if (!part) throw new Error('Empty JWT part');
                const base64 = part.replace(/-/g, '+').replace(/_/g, '/');
                atob(base64);
            });
            return true;
        } catch (error) {
            return false;
        }
    }
    
    /**
     * Sanitizes string input by removing dangerous characters and limiting length
     * @static
     * @param {string} input - The input string to sanitize
     * @param {number} [maxLength=10000] - Maximum allowed length
     * @returns {string} Sanitized string
     */
    static sanitizeString(input, maxLength = 10000) {
        if (typeof input !== 'string') return '';
        
        return input
            .replace(/[<>\"'&]/g, '')
            .substring(0, maxLength)
            .trim();
    }
    
    /**
     * Validates URL format and protocol
     * @static
     * @param {string} url - The URL to validate
     * @returns {boolean} True if URL is valid and uses http/https
     */
    static isValidURL(url) {
        if (!url || typeof url !== 'string') return false;
        
        try {
            const parsed = new URL(url);
            return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch (error) {
            return false;
        }
    }
    
    static isValidPort(port) {
        const numPort = parseInt(port, 10);
        return !isNaN(numPort) && numPort >= 1024 && numPort <= 65535;
    }
    
    static isValidAlgorithm(algorithm) {
        const validAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'none'];
        return validAlgorithms.includes(algorithm);
    }
    
    static validateFilePath(filePath) {
        if (!filePath || typeof filePath !== 'string') return false;
        
        const dangerousPatterns = [
            /\.\./,
            /[<>:"|?*]/,
            /^\/dev\//,
            /^\/proc\//,
        ];
        
        return !dangerousPatterns.some(pattern => pattern.test(filePath));
    }
    
    /**
     * Sanitizes HTTP headers by limiting count and content length
     * @static
     * @param {Object} headers - The headers object to sanitize
     * @returns {Object} Sanitized headers object
     */
    static sanitizeHeaders(headers) {
        if (!headers || typeof headers !== 'object') return {};
        
        const sanitized = {};
        const maxHeaders = 50;
        const maxHeaderLength = 8192;
        
        let count = 0;
        for (const [key, value] of Object.entries(headers)) {
            if (count >= maxHeaders) break;
            
            const sanitizedKey = this.sanitizeString(key, 256);
            const sanitizedValue = this.sanitizeString(value, maxHeaderLength);
            
            if (sanitizedKey && sanitizedValue) {
                sanitized[sanitizedKey] = sanitizedValue;
                count++;
            }
        }
        
        return sanitized;
    }
}

module.exports = ValidationUtils;