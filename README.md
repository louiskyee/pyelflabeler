# ELF Binary Labeler

[中文版本](README_zh-TW.md)

A powerful Python tool for analyzing and labeling ELF binary datasets, designed for malware and benignware classification. This tool extracts comprehensive metadata from binary files including CPU architecture, endianness, packing information, and malware family classification.

## Features

- **Dual Mode Operation**
  - **Malware Mode**: Analyze VirusTotal JSON reports combined with binary files
  - **Benignware Mode**: Direct binary analysis without JSON reports

- **Comprehensive Binary Analysis**
  - ELF header information (CPU, architecture, endianness, file type)
  - Binary metadata (bits, load segments, section headers)
  - File hashing (MD5, SHA256)
  - Packing detection using DiE (Detect It Easy)
  - Malware family classification using AVClass

- **Performance Optimized**
  - Multi-process parallel processing
  - Progress tracking with tqdm
  - Efficient single-pass file reading

## Prerequisites

### Required Tools

1. **Python 3.8+** with the following packages:
   ```bash
   pip install tqdm
   ```

2. **readelf** (part of binutils)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install binutils

   # RHEL/CentOS
   sudo yum install binutils
   ```

3. **DiE (Detect It Easy)** - for packing detection
   - Download from: https://github.com/horsicq/Detect-It-Easy
   - Ensure `diec` command is available in PATH

4. **AVClass** (Optional, for malware mode only)
   - Clone from: https://github.com/malicialab/avclass
   - Follow AVClass installation instructions
   - Ensure `avclass` command is available in PATH

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/louiskyee/elf-binary-labeler.git
   cd elf-binary-labeler
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Verify tool dependencies:
   ```bash
   readelf --version
   diec --version
   avclass --help  # Optional, for malware mode
   ```

## Usage

### Malware Mode

Analyze VirusTotal JSON reports combined with binary files:

```bash
python3 label.py --mode malware \
    -i /path/to/json_reports \
    -b /path/to/malware/binaries \
    -o malware_output.csv
```

**Expected Directory Structure:**
```
/path/to/json_reports/
├── sample1.json
├── sample2.json
└── ...

/path/to/malware/binaries/
├── 01/
│   └── 01a2b3c4...  (SHA256 hash)
├── 02/
│   └── 02d5e6f7...
└── ...
```

### Benignware Mode

Analyze binary files directly without JSON reports:

```bash
python3 label.py --mode benignware \
    -b /path/to/benignware/binaries \
    -o benignware_output.csv
```

### Command Line Options

| Option | Short | Description | Required |
|--------|-------|-------------|----------|
| `--mode` | `-m` | Analysis mode: `malware` or `benignware` | No (default: malware) |
| `--input_folder` | `-i` | Folder containing JSON reports | Yes (malware mode only) |
| `--binary_folder` | `-b` | Folder containing binary files | Yes (both modes) |
| `--output` | `-o` | Output CSV file path | No (auto-generated) |

## Output Format

The tool generates a CSV file with the following columns:

| Column | Description |
|--------|-------------|
| `file_name` | SHA256 hash of the binary |
| `md5` | MD5 hash |
| `label` | Classification: `Malware` or `Benignware` |
| `file_type` | ELF file type (EXEC, DYN, REL, CORE) |
| `CPU` | CPU architecture (e.g., x86-64, ARM) |
| `bits` | Binary bits (32 or 64) |
| `endianness` | Byte order (little/big endian) |
| `load_segments` | Number of PT_LOAD segments |
| `has_section_name` | Whether section headers exist |
| `family` | Malware family (malware mode only) |
| `first_seen` | First seen timestamp (malware mode) |
| `size` | File size in bytes |
| `diec_is_packed` | Whether binary is packed (True/False) |
| `diec_packer_info` | Packer name and version |
| `diec_packing_method` | Packing method details |

### Example Output

```csv
file_name,md5,label,file_type,CPU,bits,endianness,load_segments,has_section_name,family,first_seen,size,diec_is_packed,diec_packer_info,diec_packing_method
01a2b3c4...,5e6f7g8h...,Malware,EXEC,Advanced Micro Devices X86-64,64,2's complement little endian,2,True,mirai,2024-01-15,45678,True,UPX(3.95),NRV
```

## Error Handling

- Errors and warnings are logged to `{output_filename}_errors.log`
- Failed file analyses continue processing remaining files
- Detailed debug information available in log files

## Performance

- Utilizes all available CPU cores for parallel processing
- Optimized single-pass file reading for ELF analysis
- Progress bars for real-time status updates

Example performance (tested on 8-core system):
- ~1000 files processed in ~5-10 minutes (depending on binary sizes and analysis depth)

## Troubleshooting

### Common Issues

1. **"AVClass not found"**
   - Ensure AVClass is installed and in your PATH
   - Malware mode requires AVClass for family classification

2. **"readelf failed"**
   - Verify binutils is installed: `which readelf`
   - Some non-ELF files will skip readelf analysis

3. **"diec command failed"**
   - Ensure DiE is properly installed
   - Check `diec` is accessible: `which diec`

4. **Permission Denied**
   - Ensure read permissions on input directories
   - Ensure write permissions for output CSV location

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).

## Citation

If you use this tool in your research, please cite:

```bibtex
@software{elf_binary_labeler,
  title={ELF Binary Labeler: A Tool for Malware Dataset Analysis},
  author={louiskyee},
  year={2024},
  url={https://github.com/louiskyee/elf-binary-labeler}
}
```

## Acknowledgments

- [AVClass](https://github.com/malicialab/avclass) - Malware family classification
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) - Packer detection
- [tqdm](https://github.com/tqdm/tqdm) - Progress bars

## Contact

For questions, issues, or suggestions, please open an issue on GitHub.

---

**Note**: This tool is designed for security research and educational purposes. Use responsibly and ethically.
