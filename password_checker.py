"""
Password Strength and Breach Checker
This tool checks how strong a password is and whether it has appeared in a known data breach.
"""

import hashlib
import re
import urllib.request


def check_strength(password: str) -> list[str]:
    issues = []

    if len(password) < 8:
        issues.append("Too short - aim for at least 12 characters.")
    elif len(password) < 12:
        issues.append("Okay length, but 12+ characters is stronger.")

    if not re.search(r"[a-z]", password):
        issues.append("Missing lowercase letters.")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase letters.")
    if not re.search(r"[0-9]", password):
        issues.append("Missing numbers.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("Missing symbols such as ! @ # £.")

    common_patterns = ["password", "123456", "qwerty", "letmein", "welcome"]
    lowered = password.lower()
    for pattern in common_patterns:
        if pattern in lowered:
            issues.append(f"Contains a very common pattern: {pattern}.")

    return issues


def check_breach(password: str) -> int:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read().decode("utf-8")
    except Exception as e:
        print(f"Could not reach breach database: {e}")
        return -1

    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


def main():
    print("Password Strength and Breach Checker")
    password = input("Enter a password to check, it will not be stored: ")

    print("\nStrength Check")
    issues = check_strength(password)
    if issues:
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("  Looks strong! No obvious weaknesses found.")

    print("\nBreach Check")
    count = check_breach(password)
    if count == -1:
        print("  Could not complete breach check, check your internet connection.")
    elif count == 0:
        print("  Good news, this password was not found in any known breach.")
    else:
        print(f"  Warning: this password has appeared in {count} known breaches.")
        print("  You should not use it, even with small changes.")


if __name__ == "__main__":
