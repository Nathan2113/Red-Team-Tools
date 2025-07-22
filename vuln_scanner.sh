#!/bin/bash

# Scanning Windows machines for SMB vulnerabilities

while true; do
	if [ -f "smb_vulns.txt" ]; then
		read -p "SMB vuln file already exists...Overwrite? [y|N] " yn

		# Default to "no" if the input is empty
		if [[ -z "$yn" ]]; then
			yn="no"
		fi

		case $yn in
			[Yy]|[Yy][Ee][Ss])
				echo "Overwriting..."
				echo '' > smb_vulns.txt
				break
				;;
			[Nn]|[Nn][Oo])
				echo "Exiting..."
				exit 0
				;;
			*)
				echo "Invalid input. Please answer 'yes' or 'no'."
		esac
	else
		touch smb_vulns.txt
	fi
done


while IFS= read -r line || [[ -n "$line" ]]; do
	echo "[+] Scanning $line for SMB vulns"
	nmap -p139,445 $line --script smb-vuln* >> smb_vulns.txt
	echo -e "[+] Scan for $line complete\n "
done < $1

#while IFS= read -r line || [[ -n "$line" ]]; do
#	echo "
