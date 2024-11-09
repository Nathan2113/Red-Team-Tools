#!/bin/sh

hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt

hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt --show > cracked.txt

python3 combine.py > user_pass.txt

python3 split_user_pass.py

python3 filter_pass.py

python3 combine_filtered.py

rm user_pass.txt

rm passwords.txt

rm users.txt

mkdir credentials

mv filtered_users.txt credentials/users.txt

mv filtered_passwords.txt credentials/pass.txt

mv cracked.txt credentials/

mv user_pass_pairs.txt credentials/

