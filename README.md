# Data Encryption Standard (DES) Implementation in Python

A complete, from-scratch implementation of the Data Encryption Standard (DES) algorithm in Python, including key scheduling, Feistel rounds, S-boxes, and file encryption/decryption.

## Overview

This project implements the full DES algorithm, demonstrating the internal structure of one of the most influential block ciphers in cryptographic history. The implementation includes:

- Key schedule generation (PC-1, PC-2, left rotations)
- Initial and final permutations (IP, FP)
- Expansion permutation (E)
- S-box substitution (all 8 boxes)
- P-box permutation
- 16-round Feistel network
- PKCS#7 padding for arbitrary file lengths
- File encryption/decryption with hex output

## Features

- **Complete DES Implementation**: All components from scratch
- **Any Length Keys**: Zero padding or truncation to 8 bytes
- **File Support**: Encrypt/decrypt any file with PKCS#7 padding
- **Hex Output**: Readable hexadecimal ciphertext format
- **Self-Test**: Built-in verification using known plaintext
- **Comprehensive Comments**: Educational code with clear explanations

## Technologies Used

- Python 3
- No external dependencies

## Usage

### Self-Test

`python des.py test`

### Encrypt a File

`python des.py encrypt DES-test2026.txt "ATM_SECURE_KEY_2026" encrypted.hex`

### Decrypt a File

`python des.py decrypt encrypted.hex "ATM_SECURE_KEY_2026" recovered.txt`

## Key Features

**Key Schedule**
- 64-bit key --> 56-bit key (remove parity bits)
- Split into C0 and D0 (28 bits each)
- Left rotations per round (1 or 2 bits)
- PC-2 permutation --> 48-bit round key

**S-Boxes**
- 8 S-boxes, each 4x16 lookup table
- 6-bit input --> 4-bit output
- Provides non-linear transformation (confusion)
- Designed to resist differential cryptanalysis

## Project Context

This was developed as part of a cryptography assignment simulating an ATM transaction system's encryption module. The implementation successfully encrypts and decrypts files, handling arbitrary key lengths and file sizes with correct PKCS#7 padding.

## Results

- **Test Vector**: Successfully encrypted and decrypted DES-test2026.txt
- **File Recovery**: Decrypted output matched original exactly
- **Key Handling**: Supports any key length with zero padding/truncation
- **Padding**: Correct PKCS#7 implementation for arbitrary file sizes
