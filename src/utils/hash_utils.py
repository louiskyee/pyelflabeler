"""
Hash calculation utilities for binary files.
"""

import logging
import hashlib


def calculate_file_hashes(binary_path):
    """
    Calculate SHA256 and MD5 hashes for a binary file.

    :param binary_path: Path to the binary file
    :return: Tuple of (sha256, md5), or (None, None) if error
    """
    try:
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()

        with open(binary_path, 'rb') as f:
            # Read file in chunks to handle large files
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)

        return sha256_hash.hexdigest(), md5_hash.hexdigest()

    except Exception as e:
        logging.debug(f"Error calculating hashes for {binary_path}: {e}")
        return None, None
