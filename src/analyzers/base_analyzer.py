"""
Abstract base analyzer for dataset labeling.
"""

import os
import csv
import time
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

from src.constants import CSV_FIELDNAMES
from src.config import Config


class BaseAnalyzer(ABC):
    """Abstract base class for binary file analyzers."""

    def __init__(self, config: Config):
        """
        Initialize the BaseAnalyzer object.

        :param config: Configuration object containing input directory and output path.
        """
        self.config = config
        self.file_list = []
        self.binary_base_path = config.binary_base_path

    @abstractmethod
    def collect_files(self):
        """
        Collect files to be processed.
        This method must be implemented by subclasses.
        """
        pass

    @abstractmethod
    def process_single_file(self, file_path):
        """
        Process a single file and extract information.
        This method must be implemented by subclasses.

        :param file_path: Path to the file to process.
        :return: Dictionary containing extracted information, or None if processing failed.
        """
        pass

    def analyze_files(self):
        """
        Analyze all collected files using multiprocessing.
        This is a common implementation shared by all subclasses.
        """
        start_time = time.time()

        # Create a list to store extracted information
        results = []

        # Set the maximum number of processes, can be adjusted based on CPU cores
        max_workers = os.cpu_count()
        print(f"Using {max_workers} processes for parallel processing")

        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            # Submit all files for processing using the class's static method
            # This avoids serializing the entire self object for each task
            static_method = self.__class__.process_single_file

            # Check if process_single_file needs binary_base_path (for MalwareAnalyzer)
            # We can check the method signature
            import inspect
            sig = inspect.signature(static_method)
            needs_binary_path = 'binary_base_path' in sig.parameters

            if needs_binary_path:
                # For MalwareAnalyzer: pass binary_base_path
                futures = [executor.submit(static_method, file_path, self.binary_base_path)
                          for file_path in self.file_list]
            else:
                # For BenignwareAnalyzer: only pass file_path
                futures = [executor.submit(static_method, file_path)
                          for file_path in self.file_list]

            # Collect results with progress bar
            for future in tqdm(as_completed(futures), total=len(futures),
                             desc="Analyzing files", unit="file"):
                result = future.result()
                # Skip None results (failed processing or missing files)
                if result is not None:
                    results.append(result)

        # Sort results by file name (handle None values)
        results.sort(key=lambda x: x['file_name'] if x['file_name'] is not None else '')

        # Write to CSV file
        self.write_results(results)

        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.2f} seconds")
        print(f"Analyzed {len(results)} files")

    def write_results(self, results):
        """
        Write analysis results to CSV file.

        :param results: List of dictionaries containing analysis results.
        """
        with open(self.config.output_path, encoding="utf-8", mode='w', newline='') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
                writer.writeheader()
                writer.writerows(results)

    def run(self):
        """
        Run the complete analysis process.
        """
        self.collect_files()
        self.analyze_files()
        print(f"Output CSV path: {Path(self.config.output_path).resolve()}")
