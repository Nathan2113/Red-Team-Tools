#!/usr/bin/env python3
import sys
import argparse
import itertools

# ------------------------------------------------------
# Custom wordlist generator that will take wordlist from
# cewl and make permutations of those words to generate
# a wordlist for hashcat
# ------------------------------------------------------


# Example Usage
# cewl localhost:8000/test.php -d 3 -m 6 --with-numbers -w cewl_list.txt
## crawls the webpage with a depth of 3, only grabs words with a min length of 6

# python3 generate_wordlist.py -i cewl_list.txt -o custom_wordlist.txt --min-length 12 --numbers 1998
## inputs cewl_list.txt, has a password length requirement of 12, and includes the number 1998
### 1998 will get added to a list of common numbers to create combinations with (1, 123, 321, 777...)

# ------------------------------------------------------
# Fallback common numbers (used if --numbers not supplied)
# ------------------------------------------------------
COMMON_FALLBACK_NUMBERS = [
    "1", "01",
    "12", "21",
    "123", "321",
    "1234", "4321",
    "12345",
    "111", "222", "333", "777", "999"
]


# ------------------------------------------------------
# Helpers
# ------------------------------------------------------

def read_cewl_words(path, max_words=None):
    """Read CEWL words, optionally limiting count."""
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if w:
                words.append(w)
            if max_words and len(words) >= max_words:
                break
    return words


def variants(word):
    """Return several realistic variants of each word."""
    return {
        word,
        word.lower(),
        word.capitalize(),
        word.upper(),
    }


def passes_policy(pw, min_len, symbols_set):
    """Check if password meets the policy requirements."""
    if len(pw) < min_len:
        return False

    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(c in symbols_set for c in pw)

    return has_lower and has_upper and has_digit and has_symbol


# ------------------------------------------------------
# Candidate generator
# ------------------------------------------------------

def generate_candidates(words, numbers, symbols, min_len, out_file):
    """Generate final wordlist."""
    symbols_set = set(symbols)

    # Expand word variants
    expanded = set()
    for w in words:
        expanded.update(variants(w))

    expanded = list(expanded)

    print(f"[+] Total base variants: {len(expanded)}")

    # ---- Progress estimation ----
    count_words = len(expanded)
    count_nums = len(numbers)
    count_syms = len(symbols)

    total_pattern1 = count_words * count_nums * count_syms
    total_pairs = count_words * (count_words - 1)   # w1 != w2
    total_pattern2 = total_pairs * count_nums * count_syms
    total_pattern3 = total_pairs * count_syms * count_nums
    total_pattern4 = count_nums * count_words * count_syms

    total_candidates = total_pattern1 + total_pattern2 + total_pattern3 + total_pattern4
    print(f"[+] About to test ~{total_candidates} candidates (before policy filter)")

    processed = 0

    def update_progress():
        nonlocal processed
        processed += 1
        # Print every 100k candidates, and at the very end
        if processed % 10_000 == 0 or processed == total_candidates:
            percent = (processed / total_candidates) * 100
            print(f"\r[+] Progress: {processed}/{total_candidates} (~{percent:.2f}%)", end="", flush=True)

    written = 0

    with open(out_file, "w", encoding="utf-8") as f:

        # -----------------------------------------
        # Pattern 1: word + number + symbol
        # -----------------------------------------
        for w in expanded:
            for n in numbers:
                for s in symbols:
                    pw = f"{w}{n}{s}"
                    update_progress()
                    if passes_policy(pw, min_len, symbols_set):
                        f.write(pw + "\n")
                        written += 1

        # -----------------------------------------
        # Pattern 2: word1 + word2 + number + symbol
        # -----------------------------------------
        for w1, w2 in itertools.product(expanded, repeat=2):
            if w1 == w2:
                continue
            base = f"{w1}{w2}"
            for n in numbers:
                for s in symbols:
                    pw = f"{base}{n}{s}"
                    update_progress()
                    if passes_policy(pw, min_len, symbols_set):
                        f.write(pw + "\n")
                        written += 1

        # -----------------------------------------
        # Pattern 3: word1 + symbol + word2 + number
        # -----------------------------------------
        for w1, w2 in itertools.product(expanded, repeat=2):
            if w1 == w2:
                continue
            for s in symbols:
                for n in numbers:
                    pw = f"{w1}{s}{w2}{n}"
                    update_progress()
                    if passes_policy(pw, min_len, symbols_set):
                        f.write(pw + "\n")
                        written += 1

        # -----------------------------------------
        # Pattern 4: number + word + symbol
        # -----------------------------------------
        for n in numbers:
            for w in expanded:
                for s in symbols:
                    pw = f"{n}{w}{s}"
                    update_progress()
                    if passes_policy(pw, min_len, symbols_set):
                        f.write(pw + "\n")
                        written += 1

    print(f"[+] Wrote {written} passwords to {out_file}")


# ------------------------------------------------------
# Entry point
# ------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a custom combination wordlist from a CEWL wordlist."
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to CEWL output wordlist (input)"
    )

    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Path to output password wordlist"
    )

    parser.add_argument(
        "--min-length",
        type=int,
        default=12,
        help="Minimum password length required (default: 12)"
    )

    parser.add_argument(
        "--symbols",
        type=str,
        default="!@#$%&*?",
        help="Symbols allowed for mutations (default: !@#$%&*?)"
    )

    parser.add_argument(
        "--max-cewl",
        type=int,
        default=500,
        help="Max CEWL words to use (default: 500)"
    )

    parser.add_argument(
        "--numbers",
        type=str,
        default=None,
        help=(
            "Comma-separated list of numbers to use "
            "(example: 1998,2023,08). "
            "If omitted, a small set of common combos is used "
            "instead of a big range."
        )
    )

    args = parser.parse_args()

    print(f"[+] Reading CEWL words from {args.input}")
    words = read_cewl_words(args.input, max_words=args.max_cewl)
    print(f"[+] Loaded {len(words)} CEWL words")

    # ------------------------------------------------------
    # Number handling
    # ------------------------------------------------------
    numbers_set = set(COMMON_FALLBACK_NUMBERS)

    if args.numbers:
        user_numbers = [n.strip() for n in args.numbers.split(",") if n.strip() != ""]
        numbers_set.update(user_numbers)
        print(f"[+] Using common + user-supplied numbers: {sorted(numbers_set)}")
    else:
        print(f"[+] No numbers supplied — using common number combos: {sorted(numbers_set)}")

    numbers = list(numbers_set)


    print(f"[+] Using symbols: {args.symbols}")
    print(f"[+] Minimum password length: {args.min_length}")

    generate_candidates(words, numbers, list(args.symbols), args.min_length, args.output)


if __name__ == "__main__":
    main()

