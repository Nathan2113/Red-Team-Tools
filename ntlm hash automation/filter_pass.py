# Define the filenames
user_file = 'users.txt'
pass_file = 'passwords.txt'

# Read the users and passwords from their respective files
with open(user_file, 'r') as uf:
    users = uf.read().splitlines()

with open(pass_file, 'r') as pf:
    passwords = pf.read().splitlines()

# Identify users with "No cracked password found"
no_password_users = {user for user, password in zip(users, passwords) if password == "No cracked password found"}

# Filter out those users from both files
filtered_users = [user for user in users if user not in no_password_users]
filtered_passwords = [password for user, password in zip(users, passwords) if user not in no_password_users]

# Write the filtered users and passwords back to new files
with open('filtered_users.txt', 'w') as f:
    f.write('\n'.join(filtered_users))

with open('filtered_passwords.txt', 'w') as f:
    f.write('\n'.join(filtered_passwords))

print("Filtered users and passwords have been written to 'filtered_users.txt' and 'filtered_passwords.txt'.")
