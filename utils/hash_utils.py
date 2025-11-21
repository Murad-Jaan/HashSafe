import hashlib
import qrcode
from io import BytesIO
from PIL import Image

def get_all_algorithms():
    """Return list of all supported hashing algorithms"""
    return [
        "MD5", "SHA1", 
        "SHA224", "SHA256", "SHA384", "SHA512",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
        "BLAKE2b", "BLAKE2s",
        "SHAKE128", "SHAKE256"
    ]

def hash_text(text, algorithm):
    """
    Hash text using specified algorithm
    
    Args:
        text (str): Text to hash
        algorithm (str): Hashing algorithm name
    
    Returns:
        str: Hexadecimal hash string
    """
    text_bytes = text.encode('utf-8')
    
    algo_map = {
        "MD5": hashlib.md5,
        "SHA1": hashlib.sha1,
        "SHA224": hashlib.sha224,
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
        "SHA3-224": hashlib.sha3_224,
        "SHA3-256": hashlib.sha3_256,
        "SHA3-384": hashlib.sha3_384,
        "SHA3-512": hashlib.sha3_512,
        "BLAKE2b": hashlib.blake2b,
        "BLAKE2s": hashlib.blake2s,
    }
    
    if algorithm in ["SHAKE128", "SHAKE256"]:
        if algorithm == "SHAKE128":
            return hashlib.shake_128(text_bytes).hexdigest(16)
        else:
            return hashlib.shake_256(text_bytes).hexdigest(32)
    
    if algorithm in algo_map:
        return algo_map[algorithm](text_bytes).hexdigest()
    
    raise ValueError(f"Unsupported algorithm: {algorithm}")

def hash_file(file, algorithm):
    """
    Hash file contents using specified algorithm
    
    Args:
        file: Uploaded file object
        algorithm (str): Hashing algorithm name
    
    Returns:
        str: Hexadecimal hash string
    """
    # Reset file pointer to beginning
    file.seek(0)
    file_bytes = file.read()
    
    algo_map = {
        "MD5": hashlib.md5,
        "SHA1": hashlib.sha1,
        "SHA224": hashlib.sha224,
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
        "SHA3-224": hashlib.sha3_224,
        "SHA3-256": hashlib.sha3_256,
        "SHA3-384": hashlib.sha3_384,
        "SHA3-512": hashlib.sha3_512,
        "BLAKE2b": hashlib.blake2b,
        "BLAKE2s": hashlib.blake2s,
    }
    
    if algorithm in ["SHAKE128", "SHAKE256"]:
        if algorithm == "SHAKE128":
            return hashlib.shake_128(file_bytes).hexdigest(16)
        else:
            return hashlib.shake_256(file_bytes).hexdigest(32)
    
    if algorithm in algo_map:
        return algo_map[algorithm](file_bytes).hexdigest()
    
    raise ValueError(f"Unsupported algorithm: {algorithm}")

def detect_hash_type(hash_string):
    """
    Detect hash type based on length and character set
    
    Args:
        hash_string (str): Hash to analyze
    
    Returns:
        str: Detected hash type or None
    """
    hash_length = len(hash_string)
    
    # Check if valid hex
    try:
        int(hash_string, 16)
    except ValueError:
        return None
    
    hash_types = {
        32: "MD5 or SHAKE128",
        40: "SHA1",
        56: "SHA224 or SHA3-224",
        64: "SHA256, SHA3-256, BLAKE2s, or SHAKE256",
        96: "SHA384 or SHA3-384",
        128: "SHA512, SHA3-512, or BLAKE2b"
    }
    
    return hash_types.get(hash_length, "Unknown hash type")

def verify_hash(text, expected_hash, algorithm):
    """
    Verify if text matches expected hash
    
    Args:
        text (str): Text to verify
        expected_hash (str): Expected hash value
        algorithm (str): Hashing algorithm
    
    Returns:
        bool: True if match, False otherwise
    """
    computed_hash = hash_text(text, algorithm)
    return computed_hash.lower() == expected_hash.lower()

def generate_qr_code(data):
    """
    Generate QR code for given data
    
    Args:
        data (str): Data to encode in QR code
    
    Returns:
        PIL.Image: QR code image
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    return img