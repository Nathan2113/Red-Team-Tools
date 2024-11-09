# Define the input files
hash_file = 'hash.txt'
cracked_file = 'cracked.txt'

# Create a dictionary to store cracked passwords
cracked_passwords = {}

# Read the cracked passwords file and populate the dictionary
with open(cracked_file, 'r', encoding='utf-8') as cf:
    for line in cf:
        hash_value, password = line.strip().split(':')
        cracked_passwords[hash_value] = password

# Read the hash file and match users with cracked passwords
with open(hash_file, 'r', encoding='utf-8') as hf:
    for line in hf:
        parts = line.strip().split(':')
        username = parts[0]
        hash_value = parts[3]  # The hash is in the fourth position

        # Check if we have a cracked password for this hash
        if hash_value in cracked_passwords:
            print(f"{username}:{cracked_passwords[hash_value]}")
        else:
            print(f"{username}:No cracked password found")
