# password_checker.py
import math
import re

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "12345",
    "123456789", "1234", "111111", "1234567", "dragon",
    "letmein", "baseball", "iloveyou", "admin", "welcome"
}

KEYBOARD_SEQS = ["qwerty", "asdf", "zxcv", "1234", "abcd"]

def char_classes(password: str):
    classes = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "symbols": bool(re.search(r"[^\w\s]", password)),
    }
    return classes

def pool_size_from_classes(classes: dict):
    size = 0
    if classes["lower"]:
        size += 26
    if classes["upper"]:
        size += 26
    if classes["digits"]:
        size += 10
    if classes["symbols"]:
        # Approximate value
        size += 32
    return size or 1

def estimate_entropy(password: str) -> float:
    classes = char_classes(password)
    pool = pool_size_from_classes(classes)
    # entropy = length * log2(pool)
    return len(password) * math.log2(pool)

def detect_simple_patterns(password: str):
    pw_lower = password.lower()
    issues = []
    if password in COMMON_PASSWORDS or pw_lower in COMMON_PASSWORDS:
        issues.append("Common password")
    # repeated ones
    if re.search(r"(.)\1\1", password):
        issues.append("Repeated characters")
    # ascending/ descending numeric sequences (e.g., 1234, 4321)
    if re.search(r"0123|1234|2345|3456|4567|5678|6789", pw_lower) or re.search(r"9876|8765|7654|6543", pw_lower):
        issues.append("Numeric sequence")
    # keyboard sequences
    for s in KEYBOARD_SEQS:
        if s in pw_lower:
            issues.append(f"Keyboard sequence: '{s}'")
            break
    # short dictionary words
    if len(password) <= 4:
        issues.append("Very short password")
    return issues

def grade_from_entropy(entropy_bits: float) -> str:
    if entropy_bits < 28:
        return "Very Weak"
    if entropy_bits < 36:
        return "Weak"
    if entropy_bits < 60:
        return "Fair"
    if entropy_bits < 128:
        return "Strong"
    return "Very Strong"

def time_to_crack_seconds(entropy_bits: float, guesses_per_second: float = 1e6):
    guesses = 2 ** (entropy_bits - 1)
    return guesses / guesses_per_second

def human_time(seconds: float) -> str:
    if seconds < 1:
        return "less than 1 second"
    minute = 60
    hour = 3600
    day = 86400
    year = 31536000
    if seconds < minute:
        return f"{int(seconds)} seconds"
    if seconds < hour:
        return f"{int(seconds//minute)} minutes"
    if seconds < day:
        return f"{int(seconds//hour)} hours"
    if seconds < year:
        return f"{int(seconds//day)} days"
    return f"{seconds/year:.1f} years"

def analyze(password: str):
    ent = estimate_entropy(password)
    classes = char_classes(password)
    pool = pool_size_from_classes(classes)
    issues = detect_simple_patterns(password)
    grade = grade_from_entropy(ent)
    crack_time = human_time(time_to_crack_seconds(ent, guesses_per_second=1e6))  # 1e6 guesses/sec (example)
    return {
        "password": password,
        "length": len(password),
        "char_classes": classes,
        "pool_size": pool,
        "entropy_bits": round(ent, 2),
        "grade": grade,
        "issues": issues,
        "estimated_crack_time (1e6 gps)": crack_time
    }

if __name__ == "__main__":
    pw = input("Enter password to analyze: ").strip()
    result = analyze(pw)
    print("\n--- Password Analysis ---")
    print(f"Length: {result['length']}")
    print(f"Character classes: {result['char_classes']}")
    print(f"Estimated entropy: {result['entropy_bits']} bits")
    print(f"Pool size used: {result['pool_size']}")
    print(f"Strength grade: {result['grade']}")
    if result['issues']:
        print("Flags/issues:")
        for it in result['issues']:
            print(f" - {it}")
    print(f"Estimated time to crack (@1e6 guesses/sec): {result['estimated_crack_time (1e6 gps)']}")
    print("-------------------------\n")
