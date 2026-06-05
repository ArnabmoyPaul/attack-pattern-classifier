#!/usr/bin/env python3
"""
Download MaxMind GeoLite2 database.
Requires free MaxMind account and license key.

Usage:
    python scripts/download_geolite2.py --license-key YOUR_KEY

Or set environment variable:
    export MAXMIND_LICENSE_KEY=your_key
    python scripts/download_geolite2.py
"""

import argparse
import os
import tarfile
from pathlib import Path
import requests
from tqdm import tqdm


def download_geolite2(license_key: str, output_dir: str = "data") -> Path:
    """
    Download GeoLite2-City database.

    Args:
        license_key: MaxMind license key
        output_dir: Directory to save database

    Returns:
        Path to downloaded .mmdb file
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # GeoLite2 download URL
    url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"

    print(f"Downloading GeoLite2-City database...")

    response = requests.get(url, stream=True, timeout=300)
    response.raise_for_status()

    # Get total size
    total_size = int(response.headers.get('content-length', 0))

    # Download with progress bar
    tar_path = output_path / "GeoLite2-City.tar.gz"
    with open(tar_path, 'wb') as f:
        with tqdm(total=total_size, unit='B', unit_scale=True, desc="Downloading") as pbar:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    pbar.update(len(chunk))

    print(f"Downloaded: {tar_path}")

    # Extract
    print("Extracting database...")
    with tarfile.open(tar_path, 'r:gz') as tar:
        for member in tar.getmembers():
            if member.name.endswith('.mmdb'):
                member.name = Path(member.name).name
                tar.extract(member, output_path)
                mmdb_path = output_path / member.name
                print(f"Extracted: {mmdb_path}")
                break

    # Clean up tar file
    tar_path.unlink()
    print("Cleaned up temporary files")

    return mmdb_path


def main():
    parser = argparse.ArgumentParser(description="Download GeoLite2 database")
    parser.add_argument("--license-key", help="MaxMind license key")
    parser.add_argument("--output-dir", default="data", help="Output directory")
    args = parser.parse_args()

    # Get license key from args or environment
    license_key = args.license_key or os.environ.get("MAXMIND_LICENSE_KEY")

    if not license_key:
        print("Error: License key required. Provide via --license-key or MAXMIND_LICENSE_KEY env var")
        print("Get a free key at: https://www.maxmind.com/en/geolite2/signup")
        return 1

    try:
        mmdb_path = download_geolite2(license_key, args.output_dir)
        print(f"\nSuccess! Database saved to: {mmdb_path}")
        print("Update your config to use this path for geolocation enrichment")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
