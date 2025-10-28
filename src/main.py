"""
Main entry point for the dataset labeler CLI.
"""

import sys
import logging
import argparse
from pathlib import Path

from src.config import Config
from src.factory import create_analyzer


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
  python3 main.py --mode malware -i /path/to/json_reports -b /path/to/malware/binaries

  # Benignware mode (analyze binaries only, no JSON reports)
  python3 main.py --mode benignware -b /path/to/benignware/binaries

  # With custom output path
  python3 main.py --mode benignware -b /path/to/benignware -o custom_output.csv
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

    # Create analyzer using factory pattern
    analyzer = create_analyzer(config)

    # Run analysis
    analyzer.run()

    # Print log file summary
    print()
    print(f"Analysis complete. Error messages logged to: {log_file}")


if __name__ == "__main__":
    main()
