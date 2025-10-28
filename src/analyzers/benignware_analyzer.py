"""
Benignware analyzer - processes binary files only.
"""

import os
import sys
import logging
from tqdm import tqdm

from src.analyzers.base_analyzer import BaseAnalyzer
from src.config import Config
from src.utils.elf_utils import get_elf_info_with_pyelftools, get_elf_binary_info
from src.utils.hash_utils import calculate_file_hashes
from src.utils.packer_utils import run_diec_analysis


class BenignwareAnalyzer(BaseAnalyzer):
    """Analyzer for benignware datasets with binary files only."""

    def __init__(self, config: Config):
        """
        Initialize the BenignwareAnalyzer object.

        :param config: Configuration object containing input directory and output path.
        """
        super().__init__(config)

        # Validate benignware mode requirements
        if not os.path.isdir(self.binary_base_path):
            print(f"Error: Binary directory does not exist: {self.binary_base_path}")
            sys.exit(1)

    def collect_files(self):
        """
        Get all binary files from the binary directory.
        Files are organized as: base_dir/hash[:2]/hash
        """
        print(f"Searching for all binary files in directory: {self.binary_base_path}...")

        # Traverse the directory structure: base_dir/XX/hash
        for subdir in tqdm(os.listdir(self.binary_base_path),
                          desc="Scanning subdirectories", unit="dir"):
            subdir_path = os.path.join(self.binary_base_path, subdir)

            # Skip if not a directory or not a 2-character hex directory
            if not os.path.isdir(subdir_path) or len(subdir) != 2:
                continue

            # List all files in the subdirectory
            try:
                for filename in os.listdir(subdir_path):
                    file_path = os.path.join(subdir_path, filename)

                    # Only process regular files (not directories)
                    if os.path.isfile(file_path):
                        self.file_list.append(file_path)
            except Exception as e:
                logging.warning(f"Error reading directory {subdir_path}: {e}")
                continue

        print(f"Found {len(self.file_list)} binary files")

    @staticmethod
    def process_single_file(binary_path):
        """
        Process a single benignware binary file.

        :param binary_path: Path to the binary file.
        :return: Dictionary containing extracted information, or None if file doesn't exist.
        """
        # Check if the binary file exists before processing
        if not os.path.exists(binary_path):
            logging.debug(f"Binary file does not exist, skipping: {binary_path}")
            return None

        # Calculate hashes from the binary file
        sha256, md5 = calculate_file_hashes(binary_path)

        # Get file size
        try:
            file_size = os.path.getsize(binary_path)
        except (OSError, IOError):
            file_size = 0

        # Default values for benignware
        result = {
            'file_name': sha256 if sha256 else None,
            'md5': md5 if md5 else None,
            'label': 'Benignware',
            'file_type': None,
            'CPU': None,
            'bits': None,
            'endianness': None,
            'load_segments': None,
            'is_stripped': None,
            'has_section_name': None,
            'family': None,
            'first_seen': None,
            'size': file_size,
            'diec_is_packed': False,
            'diec_packer_info': None,
            'diec_packing_method': None
        }

        # If hash calculation failed, return early
        if not sha256:
            return result

        # Get ELF information from binary file
        if os.path.exists(binary_path):
            # Use pyelftools to get CPU, endianness, file type, and stripped status
            elf_info = get_elf_info_with_pyelftools(binary_path)
            result['CPU'] = elf_info['cpu']
            result['endianness'] = elf_info['endianness']
            result['file_type'] = elf_info['file_type']
            result['is_stripped'] = elf_info['is_stripped']

            # Run diec analysis on the binary file
            diec_is_packed, diec_packer_info, diec_packing_method = run_diec_analysis(binary_path)
            result['diec_is_packed'] = diec_is_packed
            result['diec_packer_info'] = diec_packer_info
            result['diec_packing_method'] = diec_packing_method

            # Read ELF binary once to get bits, load segments, and section headers
            binary_info = get_elf_binary_info(binary_path)
            result['bits'] = binary_info['bits']
            result['load_segments'] = binary_info['load_segments']
            result['has_section_name'] = binary_info['has_section_name']

        return result
