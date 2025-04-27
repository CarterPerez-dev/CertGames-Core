# backend/routes/security/unhackable.py
import re
import unicodedata
import string
import time
import secrets
import hashlib
import base64
import hmac
from collections import Counter
from typing import Tuple, List, Dict, Optional, Union, Any
import math

class InputValidationError(Exception):
    """Custom exception for input validation failures"""
    def __init__(self, message: str, details: Dict[str, Any] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

# =========================================================================
# ULTRA-SECURE ADMIN AUTHENTICATION INPUT VALIDATION
# =========================================================================

def validate_admin_credentials(admin_key: str, role: str) -> Tuple[bool, List[str]]:
    """
    Comprehensive validation for admin credentials with multiple layers of defense
    
    Args:
        admin_key: The password/key for admin authentication
        role: The requested role level

    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []
    stages_passed = 0
    
    # ----- STAGE 1: Basic Input Checks -----

    if admin_key is None:
        errors.append("Admin key cannot be None")
        return False, errors
        

    if not isinstance(admin_key, str):
        errors.append("Admin key must be a string")
        return False, errors
        

    try:
        admin_key = unicodedata.normalize('NFC', admin_key)
        stages_passed += 1
    except Exception as e:
        errors.append(f"Unicode normalization failed: {str(e)}")
        return False, errors
    
    # ----- STAGE 2: Length and Character Validation -----

    if len(admin_key) < 2:
        errors.append("Admin key too long")
        return False, errors
        
    if len(admin_key) > 69:
        errors.append("admin key too short")
        return False, errors
    
    # Allowed characters (alphanumeric + specific special chars)
    # This is a whitelist approach - only allow specific characters
    allowed_chars = set(string.ascii_letters + string.digits + '!@#$%^&*()_-+=[]{}|:;<>,.?~')
    disallowed_chars = [char for char in admin_key if char not in allowed_chars]
    
    if disallowed_chars:
        errors.append(f"Admin key contains disallowed characters: {', '.join(disallowed_chars)}")
        return False, errors
    
    stages_passed += 1
    
    # ----- STAGE 3: Advanced Unicode Checks -----
    # Check for homograph attacks (similar looking characters)
    homograph_detected = detect_homograph_attack(admin_key)
    if homograph_detected:
        errors.append("nope")
        return False, errors
    
    # Detect script mixing (e.g., Latin + Cyrillic)
    if detect_script_mixing(admin_key):
        errors.append("not this either")
        return False, errors
    
    # Check for invisible characters or control characters
    if contains_control_chars(admin_key):
        errors.append("ehhhhhhrrrr wrong")
        return False, errors
        
    stages_passed += 1
    
    # ----- STAGE 4: Pattern Recognition -----

    sql_patterns = [
        r"['\"].*--", 
        r"\/\*.*\*\/",
        r";\s*SELECT",
        r";\s*DROP",
        r"UNION\s+SELECT",
        r"OR\s+1\s*=\s*1"
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, admin_key, re.IGNORECASE):
            errors.append("Potential SQL injection pattern detected")
            return False, errors
    
    # Check for XSS patterns
    xss_patterns = [
        r"<script",
        r"javascript:",
        r"on\w+=['\"]\s*\w+"
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, admin_key, re.IGNORECASE):
            errors.append("Potential XSS pattern detected")
            return False, errors
            
    # Check for command injection
    cmd_patterns = [
        r";\s*\w+",
        r"\|\s*\w+",
        r"`.*`",
        r"\$\([^)]*\)"
    ]
    
    for pattern in cmd_patterns:
        if re.search(pattern, admin_key):
            errors.append("Potential command injection pattern detected")
            return False, errors
            
    stages_passed += 1
    
    # ----- STAGE 5: Entropy & Complexity Checks -----
    # Skip complexity checks for very long passwords (30+ chars)
    if len(admin_key) < 30:
        if not has_sufficient_complexity(admin_key):
            errors.append("Admin key lacks complexity (needs uppercase, lowercase, numbers, and special chars)")
            return False, errors
        
        # Calculate entropy score (randomness)
        entropy = calculate_entropy(admin_key)
        if entropy < 3.5:  # Threshold for randomness
            errors.append("Admin key entropy too low (lacks randomness)")
            return False, errors
    
    stages_passed += 1
    
    # ----- STAGE 6: Role Validation -----
    valid_roles = {"basic", "supervisor", "superadmin"}
    if role not in valid_roles:
        errors.append(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        return False, errors
        
    stages_passed += 1
    
    # ----- STAGE 7: Special Validations -----    
    # Validate excessive repetition of characters (e.g., 'aaaaa')
    if has_excessive_repetition(admin_key):
        errors.append("Admin key contains excessive character repetition")
        return False, errors
    
    # Detect keyboard patterns (e.g., 'qwerty', '12345')
    if contains_keyboard_pattern(admin_key):
        errors.append("Admin key contains keyboard pattern")
        return False, errors
        
    # Constant-time comparison to prevent timing attacks
    # This is a dummy check just to demonstrate constant-time comparison
    # In a real scenario, you'd compare against a stored value
    constant_time_compare(admin_key, "dummy_value")
    
    stages_passed += 1
    
    # All validations passed
    return True, []


# =========================================================================
# HELPER FUNCTIONS
# =========================================================================

def detect_homograph_attack(text: str) -> bool:
    """
    Detect if text contains characters from different scripts that look similar
    """
    # Map of confusable characters and their scripts
    confusables = {
        'a': {'Latin'},
        'а': {'Cyrillic'},  # Cyrillic 'a'
        'e': {'Latin'},
        'е': {'Cyrillic'},  # Cyrillic 'e'
        'o': {'Latin'},
        'о': {'Cyrillic'},  # Cyrillic 'o'
        'p': {'Latin'},
        'р': {'Cyrillic'},  # Cyrillic 'r' (looks like p)
        'c': {'Latin'},
        'с': {'Cyrillic'},  # Cyrillic 's' (looks like c)
    }
    
    # Count scripts used in the text
    scripts_used = set()
    
    for char in text.lower():
        if char in confusables:
            scripts_used.update(confusables[char])
            if len(scripts_used) > 1:
                return True
                
    return False

def detect_script_mixing(text: str) -> bool:
    """
    Detect if text mixes multiple Unicode scripts
    """
    scripts = set()
    
    for char in text:
        # Skip ASCII for this check since it's common in passwords
        if ord(char) < 128:
            continue
            
        try:
            script = unicodedata.name(char).split()[0]
            scripts.add(script)
            if len(scripts) > 1:
                return True
        except ValueError:
            # Unknown character
            continue
            
    return False

def contains_control_chars(text: str) -> bool:
    """
    Check if text contains control characters or invisible characters
    """
    for char in text:
        # Check control characters
        if unicodedata.category(char).startswith('C'):
            return True
            
        # Check zero-width characters
        if char in ('\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF'):
            return True
            
    return False

def has_sufficient_complexity(text: str) -> bool:
    """
    Check if password has sufficient complexity (uppercase, lowercase, digits, special)
    """
    has_lower = any(c.islower() for c in text)
    has_upper = any(c.isupper() for c in text)
    has_digit = any(c.isdigit() for c in text)
    has_special = any(c in string.punctuation for c in text)
    
    # Require at least 3 of the 4 types for complexity
    complexity_count = sum([has_lower, has_upper, has_digit, has_special])
    return complexity_count >= 3

def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string (measure of randomness)
    """
    if not text:
        return 0.0
        
    # Count character frequencies
    char_count = Counter(text)
    length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_count.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
        
    return entropy

def has_excessive_repetition(text: str) -> bool:
    """
    Check if the text has excessive repetition of characters (e.g., 'aaaaa')
    """
    # Look for any character repeated more than 4 times in a row
    return bool(re.search(r'(.)\1{4,}', text))

def contains_keyboard_pattern(text: str) -> bool:
    """
    Check if the text contains keyboard patterns (e.g., 'qwerty', '12345')
    """
    # Common keyboard patterns
    keyboard_patterns = [
        'qwerty', 'asdfgh', 'zxcvbn', 'yuiop', 'hjkl',
        '12345', '67890', '09876', '54321'
    ]
    
    text_lower = text.lower()
    for pattern in keyboard_patterns:
        if pattern in text_lower:
            return True
            
    # Check for sequential characters (e.g., 'abcde')
    for i in range(len(text) - 3):
        if (
            ord(text[i+1]) == ord(text[i]) + 1 and
            ord(text[i+2]) == ord(text[i]) + 2 and
            ord(text[i+3]) == ord(text[i]) + 3
        ):
            return True
            
    return False

def constant_time_compare(val1: str, val2: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks
    """
    if len(val1) != len(val2):
        # Still use hmac comparison to maintain constant time
        return hmac.compare_digest(val1.encode(), val1.encode())
    return hmac.compare_digest(val1.encode(), val2.encode())


# =========================================================================
# SANITIZATION FUNCTIONS
# =========================================================================

def sanitize_admin_key(admin_key: str) -> Tuple[str, bool, List[str]]:
    """
    Sanitize admin key for use in authentication
    
    Args:
        admin_key: The raw admin key to sanitize
    
    Returns:
        Tuple of (sanitized_key, is_valid, error_messages)
    """
    errors = []
    
    # Validate basic input
    if admin_key is None:
        return "", False, ["Admin key cannot be None"]
    
    if not isinstance(admin_key, str):
        return "", False, ["Admin key must be a string"]
    
    # Apply Unicode normalization
    try:
        admin_key = unicodedata.normalize('NFC', admin_key)
    except Exception as e:
        return "", False, [f"Unicode normalization failed: {str(e)}"]
    
    # Trim whitespace
    admin_key = admin_key.strip()
    
    # Apply sanitization - only keep allowed characters
    allowed_chars = set(string.ascii_letters + string.digits + '!@#$%^&*()_-+=[]{}|:;<>,.?~')
    sanitized_key = ''.join(c for c in admin_key if c in allowed_chars)
    
    # If sanitization changed the string, add warning
    if sanitized_key != admin_key:
        errors.append("Admin key was modified during sanitization")
    
    # Check if the sanitized key is valid
    is_valid, validation_errors = validate_admin_credentials(sanitized_key, "basic")
    errors.extend(validation_errors)
    
    return sanitized_key, is_valid, errors

def sanitize_role(role: str) -> Tuple[str, bool, List[str]]:
    """
    Sanitize and validate admin role
    
    Args:
        role: The raw role string to sanitize
    
    Returns:
        Tuple of (sanitized_role, is_valid, error_messages)
    """
    valid_roles = {"basic", "supervisor", "superadmin"}
    errors = []
    
    if role is None:
        return "basic", False, ["Role cannot be None, defaulting to 'basic'"]
    
    if not isinstance(role, str):
        return "basic", False, ["Role must be a string, defaulting to 'basic'"]
        
    # Trim whitespace and convert to lowercase for case-insensitive comparison
    sanitized_role = role.strip().lower()
    
    # Map any variant to the correct casing
    if sanitized_role == "basic" or sanitized_role == "supervisor" or sanitized_role == "superadmin":
        sanitized_role = sanitized_role  # Keep as is
    else:
        errors.append(f"Invalid role '{role}'. Must be one of: basic, supervisor, superadmin")
        sanitized_role = "basic"  # Default to basic if invalid
    
    is_valid = len(errors) == 0
    
    return sanitized_role, is_valid, errors



def secure_admin_login(admin_key: str, role: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Comprehensive secure admin login validation and sanitization
    
    Args:
        admin_key: The admin key/password provided by the user
        role: The requested role
    
    Returns:
        Tuple of (success, message, context)
    """

    sanitized_key, key_valid, key_errors = sanitize_admin_key(admin_key)
    sanitized_role, role_valid, role_errors = sanitize_role(role)
    

    context = {
        "validation_time": time.time(),
        "key_errors": key_errors,
        "role_errors": role_errors,
        "ip_address": None,  
        "request_id": secrets.token_hex(8),
        "total_error_count": len(key_errors) + len(role_errors)
    }
    

    if not key_valid or not role_valid:
        return False, "Input validation failed", context
    

    verification_hash = hashlib.sha256(sanitized_key.encode()).hexdigest()
    

    context["verification_performed"] = True
    context["key_hash_snippet"] = verification_hash[:8] + "..." + verification_hash[-8:]
    
    # Return 
    return True, "Input validation successful", context




    

