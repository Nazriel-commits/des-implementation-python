###########################################################################
#DES.py - Data Encryption Standard Implementation
#ISEC2000 - Assignment 1, Part 2
#
#Overview:
#  This program implements the full DES algorithm for encrypting and decrypting files. 
#  It simulates how an ATM system would encrypt transaction data before transmission.
#
#What it does:
#  - Takes any length password and generates 16 round keys
#  - Encrypts any file using DES (64-bit blocks, 16 Feistel rounds)
#  - Outputs ciphertext in readable hexadecimal format
#  - Decrypts hex ciphertext back to original plaintext
#  - Handles all keyboard characters (letters, numbers, symbols)
#
#Author: Nazriel Al-Hafidz | 21495959
###########################################################################

import sys

#============================================================
#Permutation tables: key for rearranging the bits
#============================================================

#Initial permutation (first shuffle of the data)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

#Final permutation (undoes the IP shuffle as it is inverse of IP)
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

#Expansion permutation (take 32 bits and makes them 48 bits
#Have to repeat some bits so that they can mix with 48 bit key)
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

#Permutation (final shuffle after S-boxes)
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

#Key schedule tables
#Takes 64 b it key, removes 8 parity bits to make it 56 bits
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

#Takes 56 bits, selects 48 bits for round key
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

#How many bits to rotate each round
#Round 1, we rotate 1 bit, round 2 rotate 1 bit, round 3 rotate 2 bits, etc
SHIFT_AMOUNTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

#============================================================
#S-BOXES (8 boxes, each 4 by 16)
#============================================================

S_BOXES = [
    #S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    #S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    #S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    #S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    #S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    #S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    #S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    #S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# ============================================================
#Data Encryption Standard (DES) Implementation
# ============================================================
class DES:
    
    def __init__(self):
        pass
    
    #Helper functions to convert between formats
    
    #Convert string to list of 0s and 1s
    #Each character becomes 8 bits (ascii)
    def string_to_bits(self, text):
        bits = []
        for char in text:
            byte = ord(char) #Get the ASCII number
            #Extract each bit from most signifaint to least
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits
    
    #Convert list of bits back to string
    #Basically just a reverse of the previous function by grouping bits into character
    def bits_to_string(self, bits):
        chars = []
        #Process 8 bits at a time
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                #Build the byte from 8 bits
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                chars.append(chr(byte))
        return ''.join(chars)
    
    #Convert bits to hex string for readable output
    #Groups 4 bits into one hex character
    def bits_to_hex(self, bits):
        hex_chars = []
        #Process 4 bits at a time
        for i in range(0, len(bits), 4):
            group = bits[i:i+4]
            if len(group) == 4: #making sure we got the full 4bits
                value = 0
                for bit in group:
                    value = (value << 1) | bit
                hex_chars.append(format(value, 'x'))
        return ''.join(hex_chars)

    #Convert hex string back to bits
    #Again basically a reverse of the previous function
    def hex_to_bits(self, hex_str):
        bits = []
        for h in hex_str:
            val = int(h, 16) #Convert hex char to number
            #Extract each of the 4 bits
            for i in range(3, -1, -1):
                bits.append((val >> i) & 1)
        return bits
    
    #Rearrange bits according to a permutation table from earlier
    #Table tells to take bit at position X and put it here
    #I put -1 because tables use 1-indexing, but Python uses 0-indexing
    def permute(self, bits, table):
        return [bits[pos - 1] for pos in table]
    
    #XOR two lists of bits
    #How data is mixed with the key in each round
    def xor_bits(self, a, b):
        return [a[i] ^ b[i] for i in range(len(a))]
    
    #Left rotate a list of bits
    #Used in the key schedule to generate different round keys
    def left_rotate(self, bits, shift):
        return bits[shift:] + bits[:shift]
    
    #Key schedule generation
    #Turns passwords into 16 round keys
    
    #Generate 16 round keys from the original key.
    #Key can be any length since I truncate to 8 bytes which is 64 bits
    def key_schedule(self, key):

        #Step 1: Convert key to 8 bytes
        key_bytes = key.encode('utf-8')
        
        #Pad or limit to 8 bytes
        if len(key_bytes) < 8:
            #Zero padding: add null bytes to reach 8 bytes
            key_bytes = key_bytes.ljust(8, b'\0')
        elif len(key_bytes) > 8:
            #Truncate to first 8 bytes
            key_bytes = key_bytes[:8]
        
        #Convert bytes into individual bits
        key_bits = []
        for byte in key_bytes:
            for i in range(7, -1, -1):
                key_bits.append((byte >> i) & 1)
        
        #Step 2: Apply PC-1 permutation to remove parity bits (8th bit)
        key_56 = self.permute(key_bits, PC1)
        
        #Step 3: Split into two 28-bit halves
        C = key_56[:28] #left half
        D = key_56[28:] #right half
        
        #Step 4: Generate 16 round keys
        round_keys = []
        for i in range(16):
            #Rotate each halfby the scheduled amount
            shift = SHIFT_AMOUNTS[i] #1 or 2 bits per round
            C = self.left_rotate(C, shift)
            D = self.left_rotate(D, shift)
            
            #Combine and apply PC-2 to get 48bit round key from 56
            combined = C + D
            round_key = self.permute(combined, PC2)
            round_keys.append(round_key)
        
        return round_keys
    
    #Expansion Permutation
    #Part of the f-function
    
    #Expand 32-bit half-block to 48 bits using E table.
    #This is part of the f-function.
    def expansion_permutation(self, half_block):
        return self.permute(half_block, E)
    
    #S-Box Substitution
    #Also known as the confusion part as it is the non-linear part of DES
    
    #Apply S-box substitution to 48-bit block.
    #Input: 48 bits, and Output: 32 bits
    def s_box_substitution(self, expanded_block):
        result = []
        
        #Split into 8 S-boxes (each one takes 6 bits, then outputs 4 bts)
        for i in range(8):
            #Take 6 bits for this S-box
            chunk = expanded_block[i*6:(i+1)*6]
            
            #Row: first and last bit (bits 0 and 5)
            row = (chunk[0] << 1) | chunk[5]
            
            #Column: middle 4 bits (bits 1-4)
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            
            #Get value from S-box
            sbox_value = S_BOXES[i][row][col]
            
            #Convert the 4bit value into individual bits
            for j in range(3, -1, -1):
                result.append((sbox_value >> j) & 1)
        
        return result
    
    #F-Function
    #Main core for each DES round

    #The function that applies confusion and diffusion
    #Called 16 times per block
    def f_function(self, right_half, round_key):

        #Step 1: Expansion from 32 bits to 48 bits
        expanded = self.expansion_permutation(right_half)
        
        #Step 2: XOR with the 48bit round key
        xored = self.xor_bits(expanded, round_key)
        
        #Step 3: S-box substitution for non-linear transformation
        sbox_output = self.s_box_substitution(xored)
        
        #Step 4: P permutation which is where diffusion comes in
        result = self.permute(sbox_output, P)
        
        return result
    
    #Encryption process
    #One 64bit block
    
    #Encrypt a single 64-bit block using DES.
    def encrypt_block(self, block_64, round_keys):

        #Step 1: Initial permutation to scramble the bits
        block = self.permute(block_64, IP)
        
        #Step 2: Split into left and right (32 bits each)
        L = block[:32]
        R = block[32:]
        
        #Step 3: For 16 rounds apply the Feistel formula
        for i in range(16):
            old_L = L[:]
            L = R[:]
            f_output = self.f_function(R, round_keys[i])
            R = self.xor_bits(old_L, f_output)
        
        #Step 4: Final swap (tho per DES spec, no swap after last round)
        #Then final permutation to undo the IP scramble
        final_block = self.permute(R + L, FP)
        
        return final_block

    #Decryption process
    #Basically the same as encryption but the keys are in reverse
    
    #Decrypt a single 64-bit block using DES.
    def decrypt_block(self, block_64, round_keys):

        #Step 1: Same initial permuatation as encryption
        block = self.permute(block_64, IP)
        
        #Step 2: once again split into left and right
        L = block[:32]
        R = block[32:]
        
        #Step 3: Round keys in reverse order this time (15 all the way down to 0)
        for i in range(15, -1, -1):
            old_L = L[:]
            L = R[:]
            f_output = self.f_function(R, round_keys[i])
            R = self.xor_bits(old_L, f_output)
        
        #Step 4: Same final permutation as encryption
        final_block = self.permute(R + L, FP)
        
        return final_block
    
    #File handling to encrypt/decrypt entire files
    
    #Add PKCS#7 padding to data so length is multiple of 8 bytes.
    #The PKCS#7 rule is to add n btyes each with value n.
    def pad_data(self, data):

        #Even if file is already multiple of 8, add full block of padding anyway
        #Reason? To ensure that padding is always detected
        padding_len = 8 - (len(data) % 8)
        if padding_len == 0:
            padding_len = 8 #Add full block when already aligned
        return data + bytes([padding_len] * padding_len)
    
    #Remove PKCS#7 padding from decrypted data
    def unpad_data(self, data):
        if not data:
            return data
        padding_len = data[-1] #Last byte = padding length
        if 1 <= padding_len <= 8:
            #Verify padding is correct
            if all(b == padding_len for b in data[-padding_len:]):
                return data[:-padding_len] #Remove padding
        return data
    
    #Encrypt a file using DES
    #Input: plaintext file, and Output: hex ciphertext file
    def encrypt_file(self, input_file, output_file, key):

        #Generate round keys from the key
        round_keys = self.key_schedule(key)
        
        #Read plaintext file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        #Add padding
        plaintext = self.pad_data(plaintext)
        
        #Encrypt each 8-byte block
        ciphertext_bits = []
        for i in range(0, len(plaintext), 8):
            block_bytes = plaintext[i:i+8]
            
            #Convert block to bits
            block_bits = []
            for byte in block_bytes:
                for j in range(7, -1, -1):
                    block_bits.append((byte >> j) & 1)
            
            #Encrypt block
            encrypted_bits = self.encrypt_block(block_bits, round_keys)
            ciphertext_bits.extend(encrypted_bits)
        
        #Convert to hex for readability
        hex_output = self.bits_to_hex(ciphertext_bits)
        
        #Write hex to output file
        with open(output_file, 'w') as f:
            f.write(hex_output)
        
        print(f"Encrypted {input_file} -> {output_file}")
        print(f"Ciphertext length: {len(hex_output)} hex characters")
        
        return hex_output
    
    #Decrypt a hex ciphertext file using DES.
    #Input: hex ciphertext file, and output: recovered plaintext file
    def decrypt_file(self, input_file, output_file, key):

        #Generate round keys from the key
        round_keys = self.key_schedule(key)
        
        #Read hex ciphertext
        with open(input_file, 'r') as f:
            hex_ciphertext = f.read().strip()
        
        #Convert hex to bits
        ciphertext_bits = self.hex_to_bits(hex_ciphertext)
        
        #Decrypt each 64-bit block
        plaintext_bytes = bytearray()
        for i in range(0, len(ciphertext_bits), 64):
            if i + 64 <= len(ciphertext_bits):
                block_bits = ciphertext_bits[i:i+64]
                
                #Decrypt block
                decrypted_bits = self.decrypt_block(block_bits, round_keys)
                
                #Convert bits to bytes
                for j in range(0, 64, 8):
                    byte = 0
                    for k in range(8):
                        byte = (byte << 1) | decrypted_bits[j + k]
                    plaintext_bytes.append(byte)
        
        #Remove padding
        plaintext_bytes = self.unpad_data(plaintext_bytes)
        
        #Write to output file
        with open(output_file, 'wb') as f:
            f.write(plaintext_bytes)
        
        print(f"Decrypted {input_file} -> {output_file}")
        print(f"Recovered {len(plaintext_bytes)} bytes")
        
        return plaintext_bytes
    
    #Test DES method with a known plaintext to verify correctness
    def test_with_sample(self):
        print("\n" + "=" * 70)
        print("DES SELF-TEST")
        print("=" * 70)
        
        #Test data
        test_key = "ATM2026"
        test_plaintext = "WITHDRAW $100.00"
        
        print(f"Key: {test_key}")
        print(f"Plaintext: {test_plaintext}")
        
        #Encrypt
        round_keys = self.key_schedule(test_key)
        
        #Convert plaintext to bytes
        plaintext_bytes = test_plaintext.encode('utf-8')
        plaintext_bytes = self.pad_data(plaintext_bytes)
        
        #Encrypt each block
        ciphertext_bits = []
        for i in range(0, len(plaintext_bytes), 8):
            block_bytes = plaintext_bytes[i:i+8]
            block_bits = []
            for byte in block_bytes:
                for j in range(7, -1, -1):
                    block_bits.append((byte >> j) & 1)
            encrypted = self.encrypt_block(block_bits, round_keys)
            ciphertext_bits.extend(encrypted)
        
        #Decrypt back
        plaintext_recovered = bytearray()
        for i in range(0, len(ciphertext_bits), 64):
            block_bits = ciphertext_bits[i:i+64]
            decrypted = self.decrypt_block(block_bits, round_keys)
            for j in range(0, 64, 8):
                byte = 0
                for k in range(8):
                    byte = (byte << 1) | decrypted[j + k]
                plaintext_recovered.append(byte)
        
        plaintext_recovered = self.unpad_data(plaintext_recovered)
        
        print(f"\nRecovered: {plaintext_recovered.decode('utf-8')}")
        
        if plaintext_recovered.decode('utf-8') == test_plaintext:
            print("\n Test passed! Encryption and decryption work correctly.")
            return True
        else:
            print("\n Test failed!")
            return False

#============================================================
#MAIN PROGRAM
#============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python des.py encrypt <input_file> <key> [output_file]")
        print("  python des.py decrypt <input_file> <key> [output_file]")
        print("  python des.py test")
        print("\nExamples for reminder:")
        print("  python des.py encrypt plaintext.txt PASSKEY123 ciphertext.hex")
        print("  python des.py decrypt ciphertext.hex PASSKEY123 recovered.txt")
        print("  python des.py test")
        return
    
    des = DES()
    command = sys.argv[1].lower()
    
    if command == "test":
        des.test_with_sample()
        
    elif command == "encrypt":
        if len(sys.argv) < 4:
            print("Error: Need input_file and key")
            return
        
        input_file = sys.argv[2]
        key = sys.argv[3]
        output_file = sys.argv[4] if len(sys.argv) > 4 else input_file + ".hex"
        
        des.encrypt_file(input_file, output_file, key)
        
    elif command == "decrypt":
        if len(sys.argv) < 4:
            print("Error: Need input_file and key")
            return
        
        input_file = sys.argv[2]
        key = sys.argv[3]
        output_file = sys.argv[4] if len(sys.argv) > 4 else input_file.replace(".hex", "_recovered.txt")
        
        des.decrypt_file(input_file, output_file, key)
        
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()