#Brute-Force Login Tester
#- Tries multiple username/password combos on a dummy login function


# Dummy system (replace with real validation in a controlled lab setup)
def login_system(username, password):
    # Example: real system would check from database
    correct_username = "admin"
    correct_password = "password123"
    return username == correct_username and password == correct_password


def brute_force(usernames, passwords):
    for user in usernames:
        for pwd in passwords:
            print(f"Trying {user}:{pwd}")
            if login_system(user, pwd):
                print(f"\n[+] Success! Username: {user}, Password: {pwd}")
                return (user, pwd)
    print("\n[-] No valid credentials found.")
    return None


if __name__ == "__main__":
    # Example wordlists
    usernames = ["admin", "user", "test"]
    passwords = ["1234", "admin", "password123", "letmein"]

    print("=== Brute-Force Login Tester ===")
    brute_force(usernames, passwords)
