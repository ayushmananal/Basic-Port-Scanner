import hashlib
import os

def hash_text(text):
    #Generate hashes for a given string
    encoded = text.encode('utf-8')
    return {
        "MD5": hashlib.md5(encoded).hexdigest(),
        "SHA1": hashlib.sha1(encoded).hexdigest(),
        "SHA256": hashlib.sha256(encoded).hexdigest()
    }

def hash_file(file_path):
    #Generate hashes for a given file.
    if not os.path.isfile(file_path):
        return None

    hashes = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256()
    }

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hashes["MD5"].update(chunk)
            hashes["SHA1"].update(chunk)
            hashes["SHA256"].update(chunk)

    return {algo: h.hexdigest() for algo, h in hashes.items()}

if __name__ == "__main__":
    choice = input("Do you want to hash (1) Text or (2) File? Enter 1 or 2: ").strip()

    if choice == "1":
        text = input("Enter the text: ")
        results = hash_text(text)
        print("\n--- Hash Results ---")
        for algo, h in results.items():
            print(f"{algo}: {h}")

    elif choice == "2":
        file_path = input("Enter file path: ").strip()
        results = hash_file(file_path)
        if results:
            print("\n--- Hash Results ---")
            for algo, h in results.items():
                print(f"{algo}: {h}")
        else:
            print("File not found. Please check the path.")
    else:
        print("Invalid choice.")
