"""
ELF binary analysis utilities using pyelftools and struct parsing.
"""

import struct
import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_e_machine


def get_elf_info_with_pyelftools(binary_path):
    """
    Get CPU, endianness, file type, and stripped status using pyelftools.

    :param binary_path: Path to the binary file.
    :return: Dictionary with 'cpu', 'endianness', 'file_type', 'is_stripped' keys, or all None if error occurs.
    """
    info = {
        'cpu': None,
        'endianness': None,
        'file_type': None,
        'is_stripped': None
    }

    try:
        with open(binary_path, 'rb') as f:
            elffile = ELFFile(f)

            machine = elffile.header['e_machine']
            info['cpu'] = describe_e_machine(machine)

            if elffile.little_endian:
                info['endianness'] = "2's complement, little endian"
            else:
                info['endianness'] = "2's complement, big endian"

            e_type = elffile.header['e_type']
            if e_type == 'ET_EXEC':
                info['file_type'] = "EXEC"
            elif e_type == 'ET_DYN':
                info['file_type'] = "DYN"
            elif e_type == 'ET_REL':
                info['file_type'] = "REL"
            elif e_type == 'ET_CORE':
                info['file_type'] = "CORE"
            else:
                info['file_type'] = e_type

            has_symtab = False
            for section in elffile.iter_sections():
                if section.name == '.symtab':
                    has_symtab = True
                    break

            info['is_stripped'] = not has_symtab

        return info

    except Exception as e:
        logging.debug(f"Error reading ELF info with pyelftools from {binary_path}: {e}")
        return info


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
