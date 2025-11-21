import hashlib
import math
import re
from pathlib import Path

# Common leaked passwords (top 100 most common - in production, use full database)
COMMON_PASSWORDS = {
    "5f4dcc3b5aa765d61d8327deb882cf99",  # password
    "e10adc3949ba59abbe56e057f20f883e",  # 123456
    "25f9e794323b453885f5181f1b624d0b",  # 123456789
    "d8578edf8458ce06fbc5bb76a58c5ca4",  # qwerty
    "5f4dcc3b5aa765d61d8327deb882cf99",  # password
    "96e79218965eb72c92a549dd5a330112",  # 111111
    "25d55ad283aa400af464c76d713c07ad",  # 12345678
    "e99a18c428cb38d5f260853678922e03",  # abc123
    "fcea920f7412b5da7be0cf42b8c93759",  # 1234567
    "698d51a19d8a121ce581499d7b701668",  # password1
}

def calculate_entropy(password):
    """
    Calculate password entropy (randomness measure)
    
    Args:
        password (str): Password to analyze
    
    Returns:
        float: Entropy in bits
    """
    charset_size = 0
    
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset_size += 32  # Special characters
    
    if charset_size == 0:
        return 0
    
    entropy = len(password) * math.log2(charset_size)
    return entropy

def analyze_password_strength(password):
    """
    Analyze password strength and provide recommendations
    
    Args:
        password (str): Password to analyze
    
    Returns:
        dict: Strength analysis results
    """
    score = 0
    recommendations = []
    
    # Length check
    length = len(password)
    if length >= 12:
        score += 30
    elif length >= 8:
        score += 20
        recommendations.append("Consider using a longer password (12+ characters)")
    else:
        score += 10
        recommendations.append("Password is too short - use at least 12 characters")
    
    # Complexity checks
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    
    complexity_count = sum([has_lower, has_upper, has_digit, has_special])
    
    if complexity_count == 4:
        score += 40
    elif complexity_count == 3:
        score += 30
        if not has_special:
            recommendations.append("Add special characters (!@#$%^&*)")
    elif complexity_count == 2:
        score += 20
        recommendations.append("Use a mix of uppercase, lowercase, numbers, and special characters")
    else:
        score += 10
        recommendations.append("Password lacks complexity - mix different character types")
    
    # Entropy check
    entropy = calculate_entropy(password)
    if entropy >= 60:
        score += 30
    elif entropy >= 40:
        score += 20
    else:
        score += 10
        recommendations.append("Increase randomness - avoid common patterns")
    
    # Common patterns check
    common_patterns = ['123', 'abc', 'password', 'qwerty', '111', '000']
    if any(pattern in password.lower() for pattern in common_patterns):
        score = max(0, score - 20)
        recommendations.append("Avoid common patterns and sequences")
    
    # Repetitive characters
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 10)
        recommendations.append("Avoid repetitive characters")
    
    if not recommendations:
        recommendations.append("Strong password! Keep it secure.")
    
    return {
        'score': min(100, score),
        'entropy': entropy,
        'length': length,
        'has_lowercase': has_lower,
        'has_uppercase': has_upper,
        'has_digits': has_digit,
        'has_special': has_special,
        'recommendations': recommendations
    }

def check_leaked_password(password):
    """
    Check if password hash appears in common leaked passwords
    (Simplified version - in production, use Have I Been Pwned API)
    
    Args:
        password (str): Password to check
    
    Returns:
        bool: True if found in leaked database
    """
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Check against common passwords
    if password_hash in COMMON_PASSWORDS:
        return True
    
    # Check against common weak passwords (simple list)
    weak_passwords = [
        'password', '123456', '123456789', 'qwerty', '12345678',
        'abc123', 'password1', 'admin', 'letmein', 'welcome'
    ]
    
    if password.lower() in weak_passwords:
        return True
    
    return False

def load_leaked_passwords(file_path):
    """
    Load leaked password hashes from file (optional feature)
    
    Args:
        file_path (str): Path to leaked passwords file
    
    Returns:
        set: Set of leaked password hashes
    """
    leaked_hashes = set()
    
    path = Path(file_path)
    if path.exists():
        with open(path, 'r') as f:
            for line in f:
                leaked_hashes.add(line.strip().lower())
    
    return leaked_hashes