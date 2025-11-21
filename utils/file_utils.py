import json
import csv
from pathlib import Path
from io import StringIO
from utils.hash_utils import hash_file

# Storage for file integrity checks
FILE_HASH_STORAGE = {}

def save_file_hash(filename, algorithm, hash_value):
    """
    Save file hash for integrity monitoring
    
    Args:
        filename (str): Name of file
        algorithm (str): Hash algorithm used
        hash_value (str): Computed hash
    """
    if filename not in FILE_HASH_STORAGE:
        FILE_HASH_STORAGE[filename] = {}
    
    FILE_HASH_STORAGE[filename][algorithm] = hash_value

def check_file_integrity(filename, file, algorithm):
    """
    Check if file hash matches stored hash
    
    Args:
        filename (str): Name of file
        file: File object
        algorithm (str): Hash algorithm
    
    Returns:
        dict: Status and hash information
    """
    current_hash = hash_file(file, algorithm)
    
    if filename not in FILE_HASH_STORAGE or algorithm not in FILE_HASH_STORAGE[filename]:
        # First time checking, store the hash
        save_file_hash(filename, algorithm, current_hash)
        return {
            'status': 'new',
            'current_hash': current_hash,
            'stored_hash': None
        }
    
    stored_hash = FILE_HASH_STORAGE[filename][algorithm]
    
    if current_hash == stored_hash:
        return {
            'status': 'match',
            'current_hash': current_hash,
            'stored_hash': stored_hash
        }
    else:
        return {
            'status': 'mismatch',
            'current_hash': current_hash,
            'stored_hash': stored_hash
        }

def detect_hash_collision(file_hashes):
    """
    Detect if multiple files have same hash (collision)
    
    Args:
        file_hashes (dict): Dictionary of filename -> {algorithm: hash}
    
    Returns:
        str or None: Collision message or None
    """
    for algorithm in ['SHA256', 'SHA512']:
        hash_to_files = {}
        
        for filename, hashes in file_hashes.items():
            if algorithm in hashes:
                h = hashes[algorithm]
                if h not in hash_to_files:
                    hash_to_files[h] = []
                hash_to_files[h].append(filename)
        
        for h, files in hash_to_files.items():
            if len(files) > 1:
                return f"Collision in {algorithm}: {', '.join(files)} have same hash!"
    
    return None

def export_hashes(hashes, format_type):
    """
    Export hashes in specified format
    
    Args:
        hashes (dict): Dictionary of algorithm -> hash
        format_type (str): Export format (TXT, CSV, JSON)
    
    Returns:
        str or bytes: Exported data
    """
    if format_type == "TXT":
        output = []
        for algo, hash_val in hashes.items():
            output.append(f"{algo}: {hash_val}")
        return "\n".join(output)
    
    elif format_type == "CSV":
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["Algorithm", "Hash"])
        for algo, hash_val in hashes.items():
            writer.writerow([algo, hash_val])
        return output.getvalue()
    
    elif format_type == "JSON":
        return json.dumps(hashes, indent=2)
    
    else:
        raise ValueError(f"Unsupported format: {format_type}")