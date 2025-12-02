#!/usr/bin/env bash

# Usage:
#   ./enum_users.sh -t 10.0.0.10 -a
#   ./enum_users.sh -t 10.0.0.10 -u USERNAME -p PASSWORD

TARGET=""
ANON=false
USER=""
PASS=""

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -t|--target) TARGET="$2"; shift ;;
        -a|--anonymous) ANON=true ;;
        -u|--username) USER="$2"; shift ;;
        -p|--password) PASS="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Check target
if [[ -z "$TARGET" ]]; then
    echo "[-] Target required. Use -t <ip>"
    exit 1
fi

# Run rpcclient depending on mode
if $ANON; then
    echo "[*] Running anonymous enumeration on $TARGET ..."
    RPC_OUT=$(rpcclient -U "" -N "$TARGET" -c "enumdomusers")
else
    if [[ -z "$USER" || -z "$PASS" ]]; then
        echo "[-] Auth mode selected but username/password missing."
        echo "Usage: ./enum_users.sh -t <ip> -u <user> -p <pass>"
        exit 1
    fi
    echo "[*] Running authenticated enumeration on $TARGET as $USER ..."
    RPC_OUT=$(rpcclient -U "$USER%$PASS" "$TARGET" -c "enumdomusers")
fi

# Extract usernames to users.txt
echo "$RPC_OUT" | awk -F'[][]' '/user:\[/{print $2}' > rpc_users.txt

echo "[+] Usernames saved to rpc_users.txt"

