# Define the input file and output files
input_file = 'user_pass.txt'
users_file = 'users.txt'
passwords_file = 'passwords.txt'

# Create empty lists to store usernames and passwords
usernames = []
passwords = []

# Read the input file and split each line
with open(input_file, 'r', encoding='utf-8') as file:
    for line in file:
        line = line.strip()  # Remove any leading/trailing whitespace
        if line:  # Check if the line is not empty
            username, password = line.split(':')
            usernames.append(username)
            passwords.append(password)

# Write usernames to users.txt
with open(users_file, 'w', encoding='utf-8') as uf:
    for username in usernames:
        uf.write(username + '\n')

# Write passwords to passwords.txt
with open(passwords_file, 'w', encoding='utf-8') as pf:
    for password in passwords:
        pf.write(password + '\n')

print("Usernames and passwords have been split into users.txt and passwords.txt.")
