import os
import re
import csv
import sys
import time
import json
import struct
import logging
import hashlib
import argparse
import tempfile
import subprocess

from tqdm import tqdm
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

# Define CSV field order
CSV_FIELDNAMES = [
    'file_name',
    'md5',
    'label',
    'file_type',
    'CPU',
    'bits',
    'endianness',
    'load_segments',
    'has_section_name',
    'family',
    'first_seen',
    'size',
    'diec_is_packed',
    'diec_packer_info',
    'diec_packing_method'
]

class Config:
    def __init__(self, mode='malware', input_dir=None, binary_dir=None, output_path=None):
        """
        Initialize the configuration object.

        :param mode: 'malware' or 'benignware'
        :param input_dir: Input directory containing JSON files (malware mode only).
        :param binary_dir: Directory containing binary files (required).
        :param output_path: Custom output path for CSV file.
        """
        self.mode = mode
        self.input_dir = input_dir

        # Set binary base path (now required)
        if not binary_dir:
            raise ValueError("binary_dir is required. Please specify the path to binary files using -b/--binary_folder")
        self.binary_base_path = binary_dir

        # Set output path
        if output_path:
            self.output_path = output_path
        else:
            self.output_path = self.get_default_output_path()

    def get_default_output_path(self):
        """
        Get the default output path for the CSV file.

        :return: Default output path based on mode.
        """
        if self.mode == 'malware':
            if self.input_dir:
                return os.path.join(self.input_dir, "malware_info.csv")
            else:
                return "malware_info.csv"
        else:  # benignware
            if self.input_dir:
                return os.path.join(self.input_dir, "benignware_info.csv")
            else:
                return "benignware_info.csv"

class MalwareAnalyzer:
    def __init__(self, config: Config):
        """
        Initialize the MalwareAnalyzer object.

        :param config: Configuration object containing input directory and output path.
        """
        self.config = config
        self.file_list = []
        # Base path for binary files from config
        self.binary_base_path = config.binary_base_path

        # Validation based on mode
        if config.mode == 'malware':
            if not config.input_dir or not os.path.isdir(config.input_dir):
                print("Error: For malware mode, input_dir must be a valid directory containing JSON files.")
                sys.exit(1)
        else:  # benignware
            if not os.path.isdir(self.binary_base_path):
                print(f"Error: Binary directory does not exist: {self.binary_base_path}")
                sys.exit(1)

    def run(self):
        """
        Run the analysis process based on mode.
        """
        if self.config.mode == 'malware':
            self.get_all_files_in_directory()
            self.analyze_files()
        else:  # benignware
            self.get_all_binary_files()
            self.analyze_benignware_files()

        print(f"Output CSV path: {Path(self.config.output_path).resolve()}")

    def get_all_files_in_directory(self):
        """
        Recursively get all JSON files in the input directory and its subdirectories (malware mode).
        """
        print(f"Searching for all JSON files in directory: {self.config.input_dir}...")

        # Use os.walk to recursively traverse the directory and all its subdirectories
        for root, dirs, files in tqdm(os.walk(self.config.input_dir), desc="Scanning directories", unit="dir"):
            for file in files:
                # Only process JSON files
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    self.file_list.append(file_path)

        print(f"Found {len(self.file_list)} JSON files")

    def get_all_binary_files(self):
        """
        Get all binary files from the binary directory (benignware mode).
        Files are organized as: base_dir/hash[:2]/hash
        """
        print(f"Searching for all binary files in directory: {self.binary_base_path}...")

        # Traverse the directory structure: base_dir/XX/hash
        for subdir in tqdm(os.listdir(self.binary_base_path), desc="Scanning subdirectories", unit="dir"):
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
    def convert_to_one_line(json_file):
        """
        Convert a JSON file to a single-line string.

        :param json_file: Path to the JSON file.
        :return: Single-line string representation of the JSON file, or None if an error occurs.
        """
        try:
            with open(json_file, encoding="utf-8") as f:
                data = json.load(f)
            return json.dumps(data, separators=(',', ':')), data
        except json.JSONDecodeError as e:
            logging.error(f"JSON file decoding error ({json_file}): {str(e)}")
            return None, None
        except Exception as e:
            logging.error(f"Error reading JSON file ({json_file}): {str(e)}")
            return None, None

    @staticmethod
    def get_elf_info_from_readelf(binary_path):
        """
        Use readelf once to get CPU, endianness, and file type information.
        This is more efficient than calling readelf separately for each field.

        :param binary_path: Path to the binary file.
        :return: Dictionary with 'cpu', 'endianness', 'file_type' keys, or all None if error occurs.
        """
        info = {
            'cpu': None,
            'endianness': None,
            'file_type': None
        }

        try:
            result = subprocess.run(
                ['readelf', '-h', binary_path],
                capture_output=True,
                text=True,
                check=True
            )

            output = result.stdout

            for line in output.splitlines():
                # Extract CPU/Machine information
                if 'Machine:' in line:
                    info['cpu'] = line.split(':', 1)[1].strip() if ':' in line else None

                # Extract endianness information
                elif 'Data:' in line and 'endian' in line:
                    info['endianness'] = line.split(':', 1)[1].strip() if ':' in line else None

                # Extract file type information
                elif 'Type:' in line:
                    file_type = line.split(':', 1)[1].strip()
                    if 'EXEC' in file_type:
                        info['file_type'] = "EXEC"
                    elif 'DYN' in file_type:
                        info['file_type'] = "DYN"
                    elif 'REL' in file_type:
                        info['file_type'] = "REL"
                    elif 'CORE' in file_type:
                        info['file_type'] = "CORE"
                    else:
                        info['file_type'] = file_type

            return info

        except subprocess.CalledProcessError as e:
            logging.debug(f"readelf failed on {binary_path}: {e.stderr if hasattr(e, 'stderr') else str(e)}")
            return info
        except Exception as e:
            logging.debug(f"Error running readelf on {binary_path}: {str(e)}")
            return info

    @staticmethod
    def get_elf_binary_info(binary_path):
        """
        Read ELF file once to get bits, load segments count, and section headers info.
        This is more efficient than reading the file multiple times.

        :param binary_path: Path to the binary file
        :return: Dictionary with 'bits', 'load_segments', 'has_section_name' keys, or all None if error
        """
        PT_LOAD = 1
        info = {
            'bits': None,
            'load_segments': None,
            'has_section_name': None
        }

        try:
            with open(binary_path, 'rb') as f:
                # Read ELF header (up to 64 bytes)
                header = f.read(64)

                if len(header) < 5:
                    return info

                # Check ELF magic number
                if header[:4] != b'\x7fELF':
                    return info

                # Fifth byte is EI_CLASS (1=32-bit, 2=64-bit)
                ei_class = header[4]
                ei_data = header[5]  # 1=little endian, 2=big endian

                # Determine bits
                if ei_class == 1:  # ELFCLASS32
                    info['bits'] = 32
                elif ei_class == 2:  # ELFCLASS64
                    info['bits'] = 64
                else:
                    return info

                # Determine endianness
                is_little_endian = (ei_data == 1)
                endian_char = '<' if is_little_endian else '>'

                # Parse header based on 32-bit or 64-bit
                if ei_class == 1:  # 32-bit ELF
                    # e_phoff at offset 28 (4 bytes)
                    # e_phentsize at offset 42 (2 bytes)
                    # e_phnum at offset 44 (2 bytes)
                    # e_shnum at offset 48 (2 bytes)
                    e_phoff = struct.unpack(f'{endian_char}I', header[28:32])[0]
                    e_phentsize = struct.unpack(f'{endian_char}H', header[42:44])[0]
                    e_phnum = struct.unpack(f'{endian_char}H', header[44:46])[0]
                    e_shnum = struct.unpack(f'{endian_char}H', header[48:50])[0]

                elif ei_class == 2:  # 64-bit ELF
                    # e_phoff at offset 32 (8 bytes)
                    # e_phentsize at offset 54 (2 bytes)
                    # e_phnum at offset 56 (2 bytes)
                    # e_shnum at offset 60 (2 bytes)
                    e_phoff = struct.unpack(f'{endian_char}Q', header[32:40])[0]
                    e_phentsize = struct.unpack(f'{endian_char}H', header[54:56])[0]
                    e_phnum = struct.unpack(f'{endian_char}H', header[56:58])[0]
                    e_shnum = struct.unpack(f'{endian_char}H', header[60:62])[0]

                # Check if has section headers
                info['has_section_name'] = e_shnum > 0

                # Count PT_LOAD segments
                f.seek(e_phoff)
                load_count = 0

                for _ in range(e_phnum):
                    ph = f.read(e_phentsize)
                    if len(ph) < 4:
                        break

                    # p_type is the first 4 bytes of each program header
                    p_type = struct.unpack(f'{endian_char}I', ph[:4])[0]
                    if p_type == PT_LOAD:
                        load_count += 1

                info['load_segments'] = load_count

                return info

        except Exception as e:
            logging.debug(f"Error reading ELF binary info from {binary_path}: {e}")
            return info

    @staticmethod
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

    @staticmethod
    def get_family_using_avclass(json_file, one_line_data):
        """
        Use AVClass to get the malware family.

        :param json_file: Path to the JSON file.
        :param one_line_data: Single-line string representation of the JSON file.
        :return: Malware family name, or None if an error occurs.
        """
        if one_line_data is None:
            return None

        # Create a temporary file using the tempfile module
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False) as tmp_file:
            tmp_file_path = tmp_file.name
            tmp_file.write(one_line_data)

        command = f"avclass -f {tmp_file_path}"
        try:
            result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
            if result.returncode == 0:
                # Extract family name
                output_parts = result.stdout.strip().split()
                family = output_parts[1] if len(output_parts) > 1 else None
            else:
                logging.warning(f"AVClass execution failed for {json_file}: return code {result.returncode}")
                if result.stderr:
                    logging.debug(f"  stderr: {result.stderr[:200]}")
                family = None
        except subprocess.CalledProcessError as e:
            logging.warning(f"AVClass command error for {json_file}: {e}")
            if e.stderr:
                logging.debug(f"  stderr: {e.stderr[:200]}")
            family = None
        except FileNotFoundError:
            # AVClass not found in PATH
            logging.error(f"AVClass not found - please install AVClass or add it to PATH")
            family = None
        except Exception as e:
            logging.warning(f"Unexpected error running AVClass on {json_file}: {str(e)}")
            family = None
        finally:
            try:
                os.remove(tmp_file_path)
            except OSError:
                pass  # Ignore errors when removing temporary file

        return family

    @staticmethod
    def clean_ansi_codes(text):
        """
        Remove ANSI escape codes from text output.
        
        :param text: Text that may contain ANSI escape codes
        :return: Clean text without ANSI codes
        """
        # ANSI escape code pattern: \x1b[...m or \x1b[...;...m etc.
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    @staticmethod
    def parse_diec_output(diec_output):
        """
        Parse diec output to extract packer information.

        :param diec_output: Output from diec command
        :return: Dictionary containing parsed packer information
        """
        result = {
            'diec_is_packed': False,
            'diec_packer_info': None,
            'diec_packing_method': None
        }
        
        # Clean ANSI codes from output
        clean_output = MalwareAnalyzer.clean_ansi_codes(diec_output)
        
        # Check if output contains "Packer"
        if "Packer" in clean_output:
            result['diec_is_packed'] = True
            
            # Find the line containing 'Packer:'
            for line in clean_output.splitlines():
                if 'Packer:' in line:
                    # Extract packer info
                    # For "Packer: UPX(3.95)" -> extract "UPX(3.95)"
                    # For "Packer: UPX(3.95)[NRV,brute]" -> extract "UPX(3.95)"
                    packer_match = re.search(r'Packer:\s*([^[]*?)(?:\[|$)', line)
                    if packer_match:
                        result['diec_packer_info'] = packer_match.group(1).strip()
                    
                    # Extract packing method
                    # For "Packer: UPX(4.02)[NRV,brute]" format, extract content within square brackets
                    simple_method_match = re.search(r'\[([^]]+)\]', line)
                    if simple_method_match:
                        result['diec_packing_method'] = simple_method_match.group(1).strip()
                    else:
                        # Try nested brackets for complex cases
                        complex_method_match = re.search(r'\[[^[]*\[([^]]+)\]', line)
                        if complex_method_match:
                            result['diec_packing_method'] = complex_method_match.group(1).strip()
                    
                    break
        
        return result

    @staticmethod
    def run_diec_analysis(binary_path):
        """
        Run diec analysis on a binary file to get packer information.

        :param binary_path: Path to the binary file.
        :return: Tuple containing (is_packed, packer_info, packing_method)
                 Returns None for string fields if analysis fails.
        """
        try:
            # Execute diec -d command
            result = subprocess.run(['diec', '-d', binary_path],
                                  capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                logging.debug(f"diec command failed with return code {result.returncode} for {binary_path}")
                return False, None, None

            # Use parse_diec_output to parse the results
            parsed_result = MalwareAnalyzer.parse_diec_output(result.stdout)

            # Convert to the expected return format
            is_packed = parsed_result.get('diec_is_packed', False)
            packer_info = parsed_result.get('diec_packer_info', None)
            packing_method = parsed_result.get('diec_packing_method', None)

            return is_packed, packer_info, packing_method

        except subprocess.TimeoutExpired:
            logging.debug(f"Timeout while running diec on {binary_path}")
            return False, None, None
        except Exception as e:
            logging.debug(f"Error running diec analysis on {binary_path}: {str(e)}")
            return False, None, None

    @staticmethod
    def process_benignware_file(binary_path):
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
        sha256, md5 = MalwareAnalyzer.calculate_file_hashes(binary_path)

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
            # Use readelf once to get CPU, endianness, and file type
            readelf_info = MalwareAnalyzer.get_elf_info_from_readelf(binary_path)
            result['CPU'] = readelf_info['cpu']
            result['endianness'] = readelf_info['endianness']
            result['file_type'] = readelf_info['file_type']

            # Run diec analysis on the binary file
            diec_is_packed, diec_packer_info, diec_packing_method = MalwareAnalyzer.run_diec_analysis(binary_path)
            result['diec_is_packed'] = diec_is_packed
            result['diec_packer_info'] = diec_packer_info
            result['diec_packing_method'] = diec_packing_method

            # Read ELF binary once to get bits, load segments, and section headers
            binary_info = MalwareAnalyzer.get_elf_binary_info(binary_path)
            result['bits'] = binary_info['bits']
            result['load_segments'] = binary_info['load_segments']
            result['has_section_name'] = binary_info['has_section_name']

        return result

    @staticmethod
    def process_file(json_file, binary_base_path=None):
        """
        Process a single JSON file, extracting required information.

        :param json_file: Path to the JSON file.
        :param binary_base_path: Base path for binary files.
        :return: Dictionary containing extracted information, or None if processing failed.
        """
        one_line_data, json_data = MalwareAnalyzer.convert_to_one_line(json_file)

        # If JSON parsing failed, return None to indicate this record should be skipped
        if json_data is None:
            return None

        # Get file metadata
        sha256 = json_data.get('sha256', None)
        md5 = json_data.get('md5', None)
        size = json_data.get('size', 0)
        first_seen = json_data.get('first_seen', None)

        # Skip this record if sha256 is missing or empty
        if not sha256:
            return None

        # Initialize result dictionary
        result = {
            'file_name': sha256,
            'md5': md5,
            'label': None,
            'file_type': None,
            'CPU': None,
            'bits': None,
            'endianness': None,
            'load_segments': None,
            'has_section_name': None,
            'family': None,
            'first_seen': first_seen,
            'size': size,
            'diec_is_packed': False,
            'diec_packer_info': None,
            'diec_packing_method': None
        }

        # Determine if it's malware
        positives = json_data.get('positives', 0)
        result['label'] = 'Malware' if positives > 0 else 'Benignware'

        # Extract endianness from gandelf information
        gandelf_info = json_data.get('additional_info', {}).get('gandelf', {}).get('header', {})
        result['endianness'] = gandelf_info.get('data', None)

        # Use AVClass to get the family
        result['family'] = MalwareAnalyzer.get_family_using_avclass(json_file, one_line_data)

        # Build the potential path for the binary file
        # Get the first two characters of sha256 as a subdirectory
        # Check if sha256 is valid before trying to access it
        if sha256 and len(sha256) >= 2:
            prefix = sha256[:2]
            binary_path = os.path.join(binary_base_path, prefix, sha256)
        else:
            binary_path = None

        # Skip this record if binary file doesn't exist
        if not binary_path or not os.path.exists(binary_path):
            logging.debug(f"Binary file does not exist, skipping record for: {sha256}")
            return None

        # Use readelf once to get CPU, endianness, and file type
        readelf_info = MalwareAnalyzer.get_elf_info_from_readelf(binary_path)
        result['CPU'] = readelf_info['cpu']
        result['endianness'] = readelf_info['endianness']
        result['file_type'] = readelf_info['file_type']

        # Run diec analysis on the binary file
        diec_is_packed, diec_packer_info, diec_packing_method = MalwareAnalyzer.run_diec_analysis(binary_path)
        result['diec_is_packed'] = diec_is_packed
        result['diec_packer_info'] = diec_packer_info
        result['diec_packing_method'] = diec_packing_method

        # Read ELF binary once to get bits, load segments, and section headers
        binary_info = MalwareAnalyzer.get_elf_binary_info(binary_path)
        result['bits'] = binary_info['bits']
        result['load_segments'] = binary_info['load_segments']
        result['has_section_name'] = binary_info['has_section_name']

        return result

    def analyze_files(self):
        """
        Analyze all JSON files using multiprocessing (malware mode).
        """
        start_time = time.time()

        # Create a list to store extracted information
        results = []

        # Set the maximum number of processes, can be adjusted based on CPU cores
        max_workers = os.cpu_count()
        print(f"Using {max_workers} processes for parallel processing")

        # Prepare parameters
        binary_base_path = self.binary_base_path

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            # Pass the binary file base path as a parameter to process_file
            futures = [executor.submit(MalwareAnalyzer.process_file, json_file, binary_base_path)
                      for json_file in self.file_list]

            for future in tqdm(as_completed(futures), total=len(futures), desc="Analyzing files", unit="file"):
                result = future.result()
                # Skip None results (failed JSON parsing or missing sha256)
                if result is not None:
                    results.append(result)

        # Sort results by file name (handle None values)
        results.sort(key=lambda x: x['file_name'] if x['file_name'] is not None else '')

        # Write to CSV file
        with open(self.config.output_path, encoding="utf-8", mode='w', newline='') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
                writer.writeheader()
                writer.writerows(results)

        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.2f} seconds")
        print(f"Analyzed {len(results)} files")

    def analyze_benignware_files(self):
        """
        Analyze all binary files using multiprocessing (benignware mode).
        """
        start_time = time.time()

        # Create a list to store extracted information
        results = []

        # Set the maximum number of processes, can be adjusted based on CPU cores
        max_workers = os.cpu_count()
        print(f"Using {max_workers} processes for parallel processing")

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            # Submit all binary files for processing
            futures = [executor.submit(MalwareAnalyzer.process_benignware_file, binary_file)
                      for binary_file in self.file_list]

            for future in tqdm(as_completed(futures), total=len(futures), desc="Analyzing benignware", unit="file"):
                result = future.result()
                # Skip None results (file doesn't exist or processing failed)
                if result is not None:
                    results.append(result)

        # Sort results by file name (SHA256, handle None values)
        results.sort(key=lambda x: x['file_name'] if x and x['file_name'] is not None else '')

        # Write to CSV file
        with open(self.config.output_path, encoding="utf-8", mode='w', newline='') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
                writer.writeheader()
                writer.writerows(results)

        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.2f} seconds")
        print(f"Analyzed {len(results)} files")

def parse_arguments():
    """
    Parse command line arguments.

    :return: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="ELF Binary Analysis Tool - Label malware or benignware datasets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Malware mode (analyze VirusTotal JSON reports + binaries)
  python3 label.py --mode malware -i /path/to/json_reports -b /path/to/malware/binaries

  # Benignware mode (analyze binaries only, no JSON reports)
  python3 label.py --mode benignware -b /path/to/benignware/binaries

  # With custom output path
  python3 label.py --mode benignware -b /path/to/benignware -o custom_output.csv
        """
    )

    parser.add_argument("--mode", "-m",
                        choices=['malware', 'benignware'],
                        default='malware',
                        help="Analysis mode: 'malware' (with JSON reports) or 'benignware' (binaries only)")

    parser.add_argument("--input_folder", "-i",
                        default=None,
                        help="Input folder containing JSON reports (required for malware mode)")

    parser.add_argument("--binary_folder", "-b",
                        default=None,
                        required=True,
                        help="Binary files folder (required)")

    parser.add_argument("--output", "-o",
                        default=None,
                        help="Output CSV file path (default: malware_info.csv or benignware_info.csv based on mode)")

    return parser.parse_args()

def setup_logging(config):
    """
    Setup logging configuration to redirect errors to log file.

    :param config: Config object with output_path
    """
    # Generate log filename based on output CSV
    csv_path = Path(config.output_path)
    log_filename = csv_path.parent / f"{csv_path.stem}_errors.log"

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, mode='w', encoding='utf-8'),
        ]
    )

    return log_filename

def main():
    """
    Main function to execute the analysis process.
    """
    args = parse_arguments()

    # Validate arguments based on mode
    if args.mode == 'malware' and not args.input_folder:
        print("Error: --input_folder (-i) is required for malware mode")
        sys.exit(1)

    # Create config
    try:
        config = Config(
            mode=args.mode,
            input_dir=args.input_folder,
            binary_dir=args.binary_folder,
            output_path=args.output
        )
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Setup logging
    log_file = setup_logging(config)

    # Print configuration
    print("="*80)
    print(f"ELF Binary Analysis Tool - {args.mode.upper()} MODE")
    print("="*80)
    print(f"Mode:           {config.mode}")
    if config.mode == 'malware':
        print(f"JSON folder:    {config.input_dir}")
    print(f"Binary folder:  {config.binary_base_path}")
    print(f"Output CSV:     {config.output_path}")
    print(f"Error log:      {log_file}")
    print("="*80)
    print()

    # Run analysis
    analyzer = MalwareAnalyzer(config)
    analyzer.run()

    # Print log file summary
    print()
    print(f"Analysis complete. Error messages logged to: {log_file}")

if __name__ == "__main__":
    main()