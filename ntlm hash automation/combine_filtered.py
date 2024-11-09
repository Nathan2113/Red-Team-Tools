# Read users and passwords from files
with open('filtered_users.txt', 'r') as user_file:
    users = [line.strip() for line in user_file]

with open('filtered_passwords.txt', 'r') as password_file:
    passwords = [line.strip() for line in password_file]

# Check if both lists have the same length
if len(users) != len(passwords):
    print("Error: The number of users and passwords do not match.")
else:
    # Combine the lists and format as "user:pass"
    user_pass_pairs = [f"{user}:{password}" for user, password in zip(users, passwords)]
    
    # Optionally, write to an output file
    with open('user_pass_pairs.txt', 'w') as output_file:
        for pair in user_pass_pairs:
            output_file.write(pair + '\n')

    # Print to console
    for pair in user_pass_pairs:
        print(pair)

