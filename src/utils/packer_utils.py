"""
Packer detection and malware family classification utilities.
"""

import os
import re
import json
import logging
import tempfile
import subprocess


def clean_ansi_codes(text):
    """
    Remove ANSI escape codes from text output.

    :param text: Text that may contain ANSI escape codes
    :return: Clean text without ANSI codes
    """
    # ANSI escape code pattern: \x1b[...m or \x1b[...;...m etc.
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


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
    clean_output = clean_ansi_codes(diec_output)

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
        parsed_result = parse_diec_output(result.stdout)

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
