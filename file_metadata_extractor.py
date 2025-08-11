import os
import sys
import mimetypes
from datetime import datetime

def extract_metadata(file_path):
    if not os.path.exists(file_path):
        print(f" OOPS! File not found: {file_path}")
        return

    metadata = {}
    metadata['File Name'] = os.path.basename(file_path)
    metadata['Absolute Path'] = os.path.abspath(file_path)
    metadata['File Size (bytes)'] = os.path.getsize(file_path)
    metadata['Creation Time'] = datetime.fromtimestamp(os.path.getctime(file_path))
    metadata['Last Modified Time'] = datetime.fromtimestamp(os.path.getmtime(file_path))
    metadata['Last Accessed Time'] = datetime.fromtimestamp(os.path.getatime(file_path))
    metadata['MIME Type'] = mimetypes.guess_type(file_path)[0] or "Unknown"

    print("\n📄 File Metadata:")
    for key, value in metadata.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python file_metadata.py <file_path>")
    else:
        extract_metadata(sys.argv[1])
