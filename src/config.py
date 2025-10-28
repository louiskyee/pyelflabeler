"""
Configuration management for the dataset labeler.
"""

import os


class Config:
    """Configuration object for dataset labeler."""

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
