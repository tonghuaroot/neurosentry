#!/usr/bin/env python3
"""
Generate a fake model file for the CTF challenge.
Creates a file with the structure of a safetensors file
but filled with random data (no real IP).
"""

import argparse
import os
import struct
import sys
from pathlib import Path


def generate_safetensors_header(model_size_bytes: int) -> bytes:
    """
    Generate a minimal safetensors header.
    Format: 8-byte length + JSON metadata
    """
    metadata = {
        "metadata": {
            "format": "pt"
        },
        "tensors": [
            {
                "name": "model.layers.0.weight",
                "shape": [4096, 4096],
                "dtype": "F32",
                "offset": 0,
                "size": model_size_bytes - 1024  # Reserve space for header
            }
        ]
    }

    import json
    header_json = json.dumps(metadata).encode('utf-8')

    # Pad to multiple of 8 bytes
    padding = (8 - (len(header_json) % 8)) % 8
    header_json += b' ' * padding

    # Length prefix (8 bytes, little endian)
    length_prefix = struct.pack('<Q', len(header_json))

    return length_prefix + header_json


def generate_model(output_path: str, size_gb: int, overwrite: bool = False):
    """Generate a fake model file."""
    size_bytes = size_gb * 1024 * 1024 * 1024
    output_path = Path(output_path)

    if output_path.exists() and not overwrite:
        print(f"Error: File already exists: {output_path}")
        print("Use --overwrite to replace it.")
        return False

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating {size_gb}GB fake model file...")
    print(f"Output: {output_path}")

    try:
        with open(output_path, 'wb') as f:
            # Write safetensors header
            header = generate_safetensors_header(size_bytes)
            f.write(header)

            # Fill with random data
            written = len(header)
            chunk_size = 1024 * 1024  # 1MB chunks

            import hashlib
            md5 = hashlib.md5()
            md5.update(header)

            while written < size_bytes:
                chunk_size = min(chunk_size, size_bytes - written)
                chunk = os.urandom(chunk_size)
                f.write(chunk)
                md5.update(chunk)
                written += chunk_size

                if written % (1024 * 1024 * 1024) == 0:  # Every GB
                    print(f"Progress: {written // (1024**3)}GB / {size_gb}GB")

            # Write MD5 checksum to separate file
            checksum_path = output_path.with_suffix('.md5')
            with open(checksum_path, 'w') as cf:
                cf.write(f"{md5.hexdigest()}  {output_path.name}\n")

            file_size = output_path.stat().st_size
            print(f"\nModel generated successfully!")
            print(f"Size: {file_size / (1024**3):.2f} GB")
            print(f"MD5: {md5.hexdigest()}")
            print(f"Checksum saved to: {checksum_path}")

            return True

    except Exception as e:
        print(f"Error generating model: {e}")
        if output_path.exists():
            output_path.unlink()
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Generate a fake safetensors model file for CTF challenge"
    )
    parser.add_argument(
        '-o', '--output',
        default='/models/llama-2-7b.safetensors',
        help='Output file path (default: /models/llama-2-7b.safetensors)'
    )
    parser.add_argument(
        '-s', '--size',
        type=int,
        default=13,
        help='Size in GB (default: 13)'
    )
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='Overwrite existing file'
    )

    args = parser.parse_args()

    if generate_model(args.output, args.size, args.overwrite):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
