# Cryptography---19CS412-classical-techqniques
NAME: Muthulakshmi D
REG:212223040122
# Caeser Cipher
Caeser Cipher using with different key values

# AIM:

To encrypt and decrypt the given message by using Ceaser Cipher encryption algorithm.

## DESIGN STEPS:

### Step 1:

Design of Caeser Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

1.	In Ceaser Cipher each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet.
2.	For example, with a left shift of 3, D would be replaced by A, E would become B, and so on.
3.	The encryption can also be represented using modular arithmetic by first transforming the letters into numbers, according to the   
    scheme, A = 0, B = 1, Z = 25.
4.	Encryption of a letter x by a shift n can be described mathematically as,
                       En(x) = (x + n) mod26
5.	Decryption is performed similarly,
                       Dn (x)=(x - n) mod26


## PROGRAM:
PROGRAM:
CaearCipher.
```
def encrypt(text, key):
    cipher = ""
    for char in text:
        if char.isupper():
            cipher += chr((ord(char) - ord('A') + key) % 26 + ord('A'))
        elif char.islower():
            cipher += chr((ord(char) - ord('a') + key) % 26 + ord('a'))
        else:
            cipher += char
    return cipher

def decrypt(cipher, key):
    plain = ""
    for char in cipher:
        if char.isupper():
            plain += chr((ord(char) - ord('A') - key) % 26 + ord('A'))
        elif char.islower():
            plain += chr((ord(char) - ord('a') - key) % 26 + ord('a'))
        else:
            plain += char
    return plain

# Taking input
plain_text = input("Enter the plain text: ")
key = int(input("Enter the key value: "))

# Encryption
cipher_text = encrypt(plain_text, key)
print("\nPLAIN TEXT:", plain_text)
print("\nENCRYPTED TEXT:", cipher_text)

# Decryption
decrypted_text = decrypt(cipher_text, key)
print("\nAFTER DECRYPTION:", decrypted_text)
```


## OUTPUT:
Simulating Caesar Cipher

Input : MUTHULAKSHMI
Encrypted Message : PXWKXODNVKPL 
Decrypted Message : MUTHULAKSHMI

![image](https://github.com/user-attachments/assets/ac014035-f555-41ff-a376-c4242a18c148)


## RESULT:
The program is executed successfully

---------------------------------

# PlayFair Cipher
Playfair Cipher using with different key values

# AIM:

To implement a program to encrypt a plain text and decrypt a cipher text using play fair Cipher substitution technique.

 
## DESIGN STEPS:

### Step 1:

Design of PlayFair Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

ALGORITHM DESCRIPTION:
The Playfair cipher uses a 5 by 5 table containing a key word or phrase. To generate the key table, first fill the spaces in the table with the letters of the keyword, then fill the remaining spaces with the rest of the letters of the alphabet in order (usually omitting "Q" to reduce the alphabet to fit; other versions put both "I" and "J" in the same space). The key can be written in the top rows of the table, from left to right, or in some other pattern, such as a spiral beginning in the upper-left-hand corner and ending in the centre.
The keyword together with the conventions for filling in the 5 by 5 table constitutes the cipher key. To encrypt a message, one would break the message into digrams (groups of 2 letters) such that, for example, "HelloWorld" becomes "HE LL OW OR LD", and map them out on the key table. Then apply the following 4 rules, to each pair of letters in the plaintext:
1.	If both letters are the same (or only one letter is left), add an "X" after the first letter. Encrypt the new pair and continue. Some   
   variants of Playfair use "Q" instead of "X", but any letter, itself uncommon as a repeated pair, will do.
2.	If the letters appear on the same row of your table, replace them with the letters to their immediate right respectively (wrapping 
   around to the left side of the row if a letter in the original pair was on the right side of the row).
3.	If the letters appear on the same column of your table, replace them with the letters immediately below respectively (wrapping around 
   to the top side of the column if a letter in the original pair was on the bottom side of the column).
4.	If the letters are not on the same row or column, replace them with the letters on the same row respectively but at the other pair of 
   corners of the rectangle defined by the original pair. The order is important – the first letter of the encrypted pair is the one that 
    lies on the same row as the first letter of the plaintext pair.
To decrypt, use the INVERSE (opposite) of the last 3 rules, and the 1st as-is (dropping any extra "X"s, or "Q"s that do not make sense in the final message when finished).


## PROGRAM:

PlayFair Cipher
```
def prepare_text(text):
    text = text.lower().replace(" ", "").replace("j", "i")
    new_text = ""
    i = 0

    while i < len(text):
        new_text += text[i]
        if i + 1 < len(text) and text[i] == text[i + 1]:
            new_text += 'x'  
        elif i + 1 < len(text):
            new_text += text[i + 1]
            i += 1
        i += 1

    if len(new_text) % 2 != 0:
        new_text += 'z'  

    return new_text

def generate_key_table(key):
    key = key.lower().replace(" ", "").replace("j", "i")
    key_square = ""

    for ch in key + "abcdefghiklmnopqrstuvwxyz":
        if ch not in key_square:
            key_square += ch

    table = [[key_square[i * 5 + j] for j in range(5)] for i in range(5)]
    return table

def find_position(table, letter):
    for i in range(5):
        for j in range(5):
            if table[i][j] == letter:
                return i, j
    return None

def encrypt(plain_text, key_table):
    cipher_text = ""
    plain_text = prepare_text(plain_text)

    for i in range(0, len(plain_text), 2):
        a, b = plain_text[i], plain_text[i + 1]
        row1, col1 = find_position(key_table, a)
        row2, col2 = find_position(key_table, b)

        if row1 == row2:  
            cipher_text += key_table[row1][(col1 + 1) % 5]
            cipher_text += key_table[row2][(col2 + 1) % 5]
        elif col1 == col2:  
            cipher_text += key_table[(row1 + 1) % 5][col1]
            cipher_text += key_table[(row2 + 1) % 5][col2]
        else:  
            cipher_text += key_table[row1][col2]
            cipher_text += key_table[row2][col1]

    return cipher_text

def decrypt(cipher_text, key_table):
    plain_text = ""

    for i in range(0, len(cipher_text), 2):
        a, b = cipher_text[i], cipher_text[i + 1]
        row1, col1 = find_position(key_table, a)
        row2, col2 = find_position(key_table, b)

        if row1 == row2:  
            plain_text += key_table[row1][(col1 - 1) % 5]
            plain_text += key_table[row2][(col2 - 1) % 5]
        elif col1 == col2:  
            plain_text += key_table[(row1 - 1) % 5][col1]
            plain_text += key_table[(row2 - 1) % 5][col2]
        else:  
            plain_text += key_table[row1][col2]
            plain_text += key_table[row2][col1]

    return plain_text

# input
print("PlayFair Cipher\n")
key = input("Enter the key: ")
plain_text = input("\nEnter the plaintext: ")

key_table = generate_key_table(key)
cipher_text = encrypt(plain_text, key_table)
decrypted_text = decrypt(cipher_text, key_table)

print("\nCipher Text:", cipher_text)
print("\nDecrypted Text:", decrypted_text)
```

## OUTPUT:

Key text: ANITHA
Plain text: MUTHULAKSHMI 
Cipher text: osharongutlt

![Screenshot 2025-03-19 092510](https://github.com/user-attachments/assets/c43b20a3-5bab-40e9-aec4-b3cbdccfd159)


   
## RESULT:
The program is executed successfully


---------------------------

## Hill Cipher
Hill Cipher using with different key values

# AIM:

To develop a simple C program to implement Hill Cipher.

## DESIGN STEPS:

### Step 1:

Design of Hill Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 
ALGORITHM DESCRIPTION:
The Hill cipher is a substitution cipher invented by Lester S. Hill in 1929. Each letter is represented by a number modulo 26. To encrypt a message, each block of n letters is multiplied by an invertible n × n matrix, again modulus 26.
To decrypt the message, each block is multiplied by the inverse of the matrix used for encryption. The matrix used for encryption is the cipher key, and it should be chosen randomly from the set of invertible n × n matrices (modulo 26).
The cipher can, be adapted to an alphabet with any number of letters. All arithmetic just needs to be done modulo the number of letters instead of modulo 26.


## PROGRAM:
PROGRAM:
Hill Cipher
```
import numpy as np

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def matrix_mod_inv(matrix, mod):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = mod_inverse(det % mod, mod)
    if det_inv is None:
        raise ValueError("Matrix is not invertible")
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int) % mod
    return (det_inv * adjugate) % mod

def text_to_numbers(text):
    return [ord(char) - 65 for char in text]

def numbers_to_text(numbers):
    return ''.join(chr((num % 26) + 65) for num in numbers)

def hill_cipher_encrypt(plaintext, key_matrix):
    plaintext = plaintext.upper().replace(" ", "")
    while len(plaintext) % 3 != 0:
        plaintext += 'X'
    plaintext_numbers = text_to_numbers(plaintext)
    plaintext_matrix = np.array(plaintext_numbers).reshape(-1, 3).T
    encrypted_matrix = (np.dot(key_matrix, plaintext_matrix) % 26).T
    return numbers_to_text(encrypted_matrix.flatten())

def hill_cipher_decrypt(ciphertext, key_matrix):
    key_matrix_inv = matrix_mod_inv(key_matrix, 26)
    ciphertext_numbers = text_to_numbers(ciphertext)
    ciphertext_matrix = np.array(ciphertext_numbers).reshape(-1, 3).T
    decrypted_matrix = (np.dot(key_matrix_inv, ciphertext_matrix) % 26).T
    return numbers_to_text(decrypted_matrix.flatten())

key_matrix = np.array([[1, 2, 1], [2, 3, 2], [2, 2, 1]])
plaintext = input("Enter plaintext: ")
ciphertext = hill_cipher_encrypt(plaintext, key_matrix)
print("Encrypted text:", ciphertext)
decrypted_text = hill_cipher_decrypt(ciphertext, key_matrix)
print("Decrypted text:", decrypted_text)
```


## OUTPUT:

Simulating Hill Cipher

Input Message : muthulakshmi
Encrypted Message : TSFGSNMOMNOU 
Decrypted Message : muthulakshmi

![Screenshot 2025-03-19 093547](https://github.com/user-attachments/assets/800e3725-584f-4a72-98ab-45d50ad2f281)


## RESULT:
The program is executed successfully

-------------------------------------------------

# Vigenere Cipher
Vigenere Cipher using with different key values

# AIM:

To develop a simple C program to implement Vigenere Cipher.

## DESIGN STEPS:

### Step 1:

Design of Vigenere Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 
ALGORITHM DESCRIPTION:
The Vigenere cipher is a method of encrypting alphabetic text by using a series of different Caesar ciphers based on the letters of a keyword. It is a simple form of polyalphabetic substitution.To encrypt, a table of alphabets can be used, termed a Vigenere square, or Vigenere table. It consists of the alphabet written out 26 times in different rows, each alphabet shifted cyclically to the left compared to the previous alphabet, corresponding to the 26 possible Caesar ciphers. At different points in the encryption process, the cipher uses a different alphabet from one of the rows used. The alphabet at each point depends on a repeating keyword.



## PROGRAM:
PROGRAM:
Vigenere Cipher
```
def vigenere_encrypt(text, key):
    text_len = len(text)
    key_len = len(key)
    encrypted_text = list(text)
    
    for i in range(text_len):
        c = text[i]
        if 'A' <= c <= 'Z':
            encrypted_text[i] = chr(((ord(c) - ord('A') + ord(key[i % key_len]) - ord('A')) % 26) + ord('A'))
        elif 'a' <= c <= 'z':
            encrypted_text[i] = chr(((ord(c) - ord('a') + ord(key[i % key_len]) - ord('A')) % 26) + ord('a'))
    
    return "".join(encrypted_text)

def vigenere_decrypt(text, key):
    text_len = len(text)
    key_len = len(key)
    decrypted_text = list(text)
    
    for i in range(text_len):
        c = text[i]
        if 'A' <= c <= 'Z':
            decrypted_text[i] = chr(((ord(c) - ord('A') - (ord(key[i % key_len]) - ord('A')) + 26) % 26) + ord('A'))
        elif 'a' <= c <= 'z':
            decrypted_text[i] = chr(((ord(c) - ord('a') - (ord(key[i % key_len]) - ord('A')) + 26) % 26) + ord('a'))
    
    return "".join(decrypted_text)

key = input("enter key:") 
message = input("\nenter plain text:")  

# Encrypt the message
encrypted_message = vigenere_encrypt(message, key)
print("\nEncrypted Message:", encrypted_message)

# Decrypt the message
decrypted_message = vigenere_decrypt(encrypted_message, key)
print("\nDecrypted Message:", decrypted_message)
```

## OUTPUT:

Simulating Vigenere Cipher

Key: 3
Input Message : muthulakshmi
Encrypted Message : ygftgxmwetyu
Decrypted Message : muthulakshmi

![Screenshot 2025-03-19 094202](https://github.com/user-attachments/assets/b46b6bd6-03f0-49a9-b7f7-a64ae6aa5204)


## RESULT:
The program is executed successfully

-----------------------------------------------------------------------

# Rail Fence Cipher
Rail Fence Cipher using with different key values

# AIM:

To develop a simple C program to implement Rail Fence Cipher.

## DESIGN STEPS:

### Step 1:

Design of Rail Fence Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 
ALGORITHM DESCRIPTION:
In the rail fence cipher, the plaintext is written downwards and diagonally on successive "rails" of an imaginary fence, then moving up when we reach the bottom rail. When we reach the top rail, the message is written downwards again until the whole plaintext is written out. The message is then read off in rows.

## PROGRAM:

PROGRAM:
Rail Fence Cipher
```
def rail_fence_encrypt(message, rails):
    len_msg = len(message)
    code = [['\n'] * len_msg for _ in range(rails)]  # Initialize grid with newlines
    
    row, direction = 0, 1  # Start at row 0, moving downward
    for j in range(len_msg):
        code[row][j] = message[j]
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1  # Change direction at top or bottom

    encrypted_text = ''.join(code[i][j] for i in range(rails) for j in range(len_msg) if code[i][j] != '\n')
    return encrypted_text

def rail_fence_decrypt(encrypted_text, rails):
    len_msg = len(encrypted_text)
    code = [['\n'] * len_msg for _ in range(rails)]
    
    # Mark the zigzag pattern positions
    row, direction = 0, 1
    for j in range(len_msg):
        code[row][j] = '*'
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1

    # Fill the pattern with the actual encrypted characters
    index = 0
    for i in range(rails):
        for j in range(len_msg):
            if code[i][j] == '*' and index < len_msg:
                code[i][j] = encrypted_text[index]
                index += 1

    # Read the message in a zigzag pattern
    row, direction = 0, 1
    decrypted_text = []
    for j in range(len_msg):
        decrypted_text.append(code[row][j])
        row += direction
        if row == rails - 1 or row == 0:
            direction *= -1

    return ''.join(decrypted_text)

# Input from user
message = input("Enter a Secret Message: ")
rails = int(input("\nEnter number of rails: "))

# Encrypt and Decrypt
encrypted_message = rail_fence_encrypt(message, rails)
decrypted_message = rail_fence_decrypt(encrypted_message, rails)

# Output results
print("\nEncrypted Message:", encrypted_message)
print("\nDecrypted Message:", decrypted_message)
```

## OUTPUT:
Rail Fence Cipher
Enter a Secret Message : muthulakshmi
Enter number of rails 3
Encrypted Message: musuhlkhitam
Decrypted Message: muthulakshmi

![image](https://github.com/user-attachments/assets/a02281ad-b611-4788-a193-148b9143c20c)


## RESULT:
The program is executed successfully
