"""
Al Muqshith Shifan #100862739
Arshia Mortazavinezhad #100860353
Yousif Iskander #100851999

The purpose of this program is to encrypt a string given by the user using different cipher methods,
Ciphers such as Caesar, Playfair, Substation, Product and Transposition
This program then displays all the encrypted text with their respective methods used as well it will
decrypt the encrypted text and display it and the very end of the output

Made on March 10, 2023
"""

import random


class Message:
    # this class pass the user input and the crypto-system to plaintext and ciphertext classes
    def __init__(self, strings, cryptography):
        # this method is called from initialize two protected variables strings and cryptography
        self._strings = strings
        self._cryptography = cryptography

    def displayText(self):
        pass

    def __str__(self):
        return f"{self._strings} and {self._cryptography}"


class plaintextMsg(Message):
    # takes the user input and the crypto-system and encrypts the input with respect of the system

    def __init__(self):
        # this method initializes one private list list_strings and one protected list encrypted_strings
        self.__list_strings = []
        self._encrypted_strings = []

    def storeString(self, strings, cryptography):
        # this method stores the
        self.__list_strings.append([strings, cryptography])

    def Caesar_cipher(self, strings):
        # this method encrypts the input using Caesar cipher
        cipher_dict = {'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6, 'h': 7, 'i': 8, 'j': 9, 'k': 10, 'l': 11,
                       'm': 12, 'n': 13, 'o': 14, 'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19, 'u': 20, 'v': 21,
                       'w': 22, 'x': 23, 'y': 24, 'z': 25, " ": " "}
        # this dictionary maps the letters to their respective numbers

        cipher_text = []  # stores the cipher text
        plain_text = []  # stores the plain text
        encrypt_key = random.randint(0, 25)  # generates a random number between 0 and 25
        # shift_keys
        plain_text.extend(list(strings))  # stores the input as individual letters in the plain text list

        for letter in plain_text:
            if letter == " ":
                # if the letter is a space it appends a space to the cipher text
                cipher_text.append(" ")
            else:
                letter_math = cipher_dict[letter]
                # if the letter is not a space it takes the corresponding number from the dictionary and stores it in
                # letter_math
                letter_crypto = ((letter_math + encrypt_key) % 26)
                # puts the corresponding number in the mathematical formula and encrypts it with the encrypt_key
                for key, value in cipher_dict.items():
                    # takes the new letter from the dictionary with respect to the new number stored in letter_crypto
                    if value == letter_crypto:
                        # if the new letter mathematical value is equal to the letter_crypto it appends it to the
                        # cipher text
                        cipher_text.append(key)

        result = "".join(cipher_text)
        # makes a  string from the cipher text
        self._encrypted_strings.append([strings, cryptography, result, encrypt_key])
        # stores the result in the list of encrypted strings
        return result, encrypt_key, cryptography

    def Playfair_cipher(self, strings, key):

        def convertPlainTextToDiagraphs(plainText):

            # append X if Two letters are being repeated
            for i in range(0, len(plainText) + 1, 2):
                if i < len(plainText) - 1:
                    if plainText[i] == plainText[i + 1]:
                        plainText = plainText[:i + 1] + 'X' + plainText[i + 1:]

            # append X if the total letters are odd, to make plaintext even
            if len(plainText) % 2 != 0:
                plainText = plainText[:] + 'X'

            return plainText

        def generateKeyMatrix(key):

            matrix = [[0 for i in range(5)] for j in range(5)]

            KeyArr = []

            for c in key:
                if c not in KeyArr:
                    if c == 'J':
                        KeyArr.append('I')
                    else:
                        KeyArr.append(c)

            is_I = "I" in KeyArr

            for i in range(65, 91):
                if chr(i) not in KeyArr:
                    # We want I in the KeyArr not J

                    if i == 73 and not is_I:
                        KeyArr.append("I")
                        is_I = True
                    elif i == 73 or i == 74 and is_I:
                        pass
                    else:
                        KeyArr.append(chr(i))

            index = 0
            for i in range(0, 5):
                for j in range(0, 5):
                    matrix[i][j] = KeyArr[index]
                    index += 1

            return matrix

        def indexLocator(char, cipherKeyMatrix):
            indexOfChar = []

            # convert the character value from J to I
            if char == "J":
                char = "I"

            for i, j in enumerate(cipherKeyMatrix):
                # i,j will map to tuples of above array

                # j refers to inside matrix
                for a, b in enumerate(j):

                    if char == b:
                        indexOfChar.append(i)
                        indexOfChar.append(a)
                        return indexOfChar

        def encryption(plainText, key):
            cipherText = []

            keyMatrix = generateKeyMatrix(key)

            i = 0
            while i < len(plainText):

                node1 = indexLocator(plainText[i], keyMatrix)
                node2 = indexLocator(plainText[i + 1], keyMatrix)

                if node1[1] == node2[1]:
                    i1 = (node1[0] + 1) % 5
                    j1 = node1[1]

                    i2 = (node2[0] + 1) % 5
                    j2 = node2[1]
                    cipherText.append(keyMatrix[i1][j1])
                    cipherText.append(keyMatrix[i2][j2])
                    cipherText.append(", ")


                elif node1[0] == node2[0]:
                    i1 = node1[0]
                    j1 = (node1[1] + 1) % 5

                    i2 = node2[0]
                    j2 = (node2[1] + 1) % 5
                    cipherText.append(keyMatrix[i1][j1])
                    cipherText.append(keyMatrix[i2][j2])
                    cipherText.append(", ")



                else:
                    i1 = node1[0]
                    j1 = node1[1]

                    i2 = node2[0]
                    j2 = node2[1]

                    cipherText.append(keyMatrix[i1][j2])
                    cipherText.append(keyMatrix[i2][j1])
                    cipherText.append(", ")

                i += 2
            return cipherText

        XsAndSpaces = self.XsAndSpaces(strings)

        plainText = strings.replace(" ", "").upper()
        key = key.replace(" ", "").upper()

        convertedPlainText = convertPlainTextToDiagraphs(plainText)

        cipherText = " ".join(encryption(convertedPlainText, key))

        result = cipherText
        shift_keys = key
        self._encrypted_strings.append([strings, cryptography, cipherText, key])

        return result, shift_keys, cryptography, XsAndSpaces

    def Substitution_cipher(self, strings):
        # Define a list of letters, digits, and special characters to use as the basis for the substitution cipher
        mapper = list('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+`-={}|[]\\:;"\'<>,.?/')
        # Shuffle the list to create a random key for the cipher
        random.shuffle(mapper)
        # Create a dictionary that maps each character to a corresponding character in the key
        encrypt_map = dict(zip(list('abcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()_+`-={}|[]\\:;"\'<>,.?/'), mapper))
        # Initialize a list to store the encrypted characters
        cipher_text = []

        # Iterate over each character in the input string
        for letter in strings.lower():
            # If the character is in the encrypt_map dictionary, append the corresponding cipher character to the cipher_text list
            if letter in encrypt_map:
                cipher_text.append(encrypt_map[letter])

        # Join the list of cipher characters into a single string and return it
        result = ''.join(cipher_text)
        XsAndSpaces = self.XsAndSpaces(strings)


        if cryptography != "Product_cipher":
            # checks if product cipher is what's calling the method
            self._encrypted_strings.append([strings, cryptography, result, encrypt_map])
            # if product cipher is calling the method it stores the result in a list
            # to be used in the next step
            return result, encrypt_map, cryptography, XsAndSpaces
        else:
            return result, encrypt_map, cryptography, XsAndSpaces

    def Transposition_cipher(self, strings):

        # Generate a random list of 5 integers between 1 and 5 to use as the cipher key
        cipher = [2, 4, 1, 5, 3]

        # Convert the input string to uppercase and remove any spaces
        plaintext = "".join(strings.split(" ")).upper()

        for pad in range(0, len(plaintext) % len(cipher) * -1 % len(cipher)):
            plaintext += "X"

        ciphertext = ""

        for offset in range(0, len(plaintext), len(cipher)):
            for element in [a - 1 for a in cipher]:
                ciphertext += plaintext[offset + element]
            ciphertext += " "

        # Remove the trailing space from the ciphertext and return it
        result = ciphertext[:-1]
        XsAndSpaces = self.XsAndSpaces(strings)


        if cryptography != "Product_cipher":
            self._encrypted_strings.append([strings, cryptography, result, cipher])
            return result, cipher, cryptography, XsAndSpaces
        else:
            return result, cipher, cryptography, XsAndSpaces

    def Product_cipher(self, strings):
        # this method encrypts the string using multiple ciphers
        keys = []  # this list stores the keys for each cipher

        pass_1 = self.Substitution_cipher(strings)
        # pass one uses the substitution cipher to encrypt the string
        key1 = pass_1[1]
        encrypted_string = pass_1[0]

        pass_2 = self.Transposition_cipher(encrypted_string)
        # pass two uses the transposition cipher to encrypt the string
        result = pass_2[0]
        key2 = pass_2[1]
        xSpace = pass_2[3]

        keys.append(key1)
        ''' these two store thw keys for each cipher'''
        keys.append(key2)

        self._encrypted_strings.append([strings, cryptography, result, keys])

        return result, keys, cryptography, xSpace

    def Rsa_cipher(self, strings):

        strings = strings.strip()

        def gcd(a, b):
            """
            Compute the greatest common divisor of a and b using Euclid's algorithm.
            """
            if b == 0:
                return a
            else:
                return gcd(b, a % b)

        def is_coprime(a, b):
            """
            Check if a and b are coprime (i.e. their greatest common divisor is 1).
            """
            return gcd(a, b) == 1

        def generate_coprime(min_value, max_value, phi_n):
            """
            Generate a random number between min_value and max_value that is coprime with phi_n.
            """
            e = random.randint(min_value, max_value)
            while not is_coprime(e, phi_n):
                e = random.randint(min_value, max_value)
            return e

        def is_prime(n):
            """
            Check if a number is prime using trial division.
            """
            if n <= 1:
                return False
            elif n <= 3:
                return True
            elif n % 2 == 0 or n % 3 == 0:
                return False
            i = 5
            while i * i <= n:
                if n % i == 0 or n % (i + 2) == 0:
                    return False
                i += 6
            return True

        def generate_prime(min_value, max_value):
            """
            Generate a random prime number between min_value and max_value.
            """
            p = random.randint(min_value, max_value)
            while not is_prime(p):
                p = random.randint(min_value, max_value)
            return p

        # Generate two random prime numbers p and q
        min_value = 2 ** 12
        max_value = 2 ** 13
        p = generate_prime(min_value, max_value)
        q = generate_prime(min_value, max_value)

        # Calculate n and phi(n)
        n = p * q
        phi_n = (p - 1) * (q - 1)

        # Choose a value for e
        e = generate_coprime(2, phi_n, phi_n)

        # Calculate d such that d*e ≡ 1 mod phi(n)
        d = pow(e, -1, phi_n)

        # Convert string to bytes
        message = strings.encode()

        # Encrypt the message using the public key (e, n)
        encrypted = [pow(b, e, n) for b in message]

        # Decrypt the message using the private key (d, n)
        decrypted = [pow(b, d, n) for b in encrypted]

        # Convert bytes back to string
        decrypted_string = bytes(decrypted).decode(errors='ignore')  # !!!!

        keys = [encrypted, d, n]

        self._encrypted_strings.append([strings, cryptography, encrypted, keys])

        result = encrypted

        return result, keys, cryptography

    def XsAndSpaces(self, strings):
        # this method stores the Xs and Spaces
        XsAndSpaces = []
        temp_plain = []  # stores the plain text for temporary uses
        temp_plain.extend(strings)  # breaks the plain text into individual letters and stores it in a list
        x_indexes = 0
        space_indexes = 0
        isSpace = False
        for letter in temp_plain:
            if letter == " ":
                # appends all the spaces with their index in a list for future use
                index = temp_plain.index(letter)  # stores the index of the first occurrence of the letter
                index = temp_plain.index(letter,
                                         index + space_indexes)  # keeps going to the next occurrence of the letter
                XsAndSpaces.append((letter, index))
                isSpace = True
            elif letter == "x":
                # appends all the Xs with their index in a list for future use
                index = temp_plain.index(letter)  # stores the index of the first occurrence of the letter
                index = temp_plain.index(letter, index + x_indexes)  # keeps going to the next occurrence of the letter
                XsAndSpaces.append((letter, index))
                isSpace = False
                x_indexes += 1  # goes to the next occurrence of the letter

            if isSpace == True:
                space_indexes = space_indexes + 1  # goes to the next occurrence of the letter

        return XsAndSpaces

    def displayText(self):
        # displays the results
        for strings, cryptography, result, shift_keys in self._encrypted_strings:
            print(
                f"Original Plaintext: {strings}"
                f"\nEncrypted Text: {result}"
                f"\nEncryption Method: {cryptography}\n")

    def __str__(self):
        return f"{self._strings} and {self._cryptography}"


class ciphertextMsg(Message):

    def __init__(self, _encrypted_strings):
        # initiates two private lists  __encrypted_strings and __decrypted_strings
        self.__encrypted_strings_display = []
        self.__decrypted_text = []

    def Store(self, encrypted):
        # stores the encrypted text to private list __encrypted_strings_display
        self.__encrypted_strings_display.append(encrypted)

    def Decrypt_Caesar(self, encrypted_text):
        # this method decrypted the encrypted text passed to it from
        # Caesar cipher

        cipher_dict = {'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6, 'h': 7, 'i': 8, 'j': 9, 'k': 10, 'l': 11,
                       'm': 12, 'n': 13, 'o': 14, 'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19, 'u': 20, 'v': 21,
                       'w': 22, 'x': 23, 'y': 24, 'z': 25, " ": " "}

        encrypt_key = encrypted_text[1]

        plain_text = []
        cipher_text = []
        cipher_text.extend(list(encrypted_text[0]))

        for letter in cipher_text:
            # adds the spaces
            if letter == " ":
                plain_text.append(" ")
            else:
                # goes through the dictionary and takes the mathematically encoded value of the letter
                letter_math = cipher_dict[letter]
                letter_decrypt = ((letter_math - encrypt_key) % 26)  # dose the calculations necessary using the key
                # to bring back the original mathematical value of the letter
                for key, value in cipher_dict.items():
                    # takes the letter corresponded with the new value and appends it to a list
                    if value == letter_decrypt:
                        plain_text.append(key)

        result = "".join(plain_text)

        self.__decrypted_text .append(result)

    def Decrypt_Playfair(self, encrypted_text):

        cipherText = encrypted_text[0].replace(",", "")
        # takes the encrypted text and replaces the ','s with spaces
        key = encrypted_text[1]
        # takes encryption key metrix used
        xSpace = encrypted_text[3]

        # takes the list of original Xs and Spaces that hve been removed

        def generateKeyMatrix(key):

            matrix = [[0 for i in range(5)] for j in range(5)]

            KeyArr = []

            for c in key:
                if c not in KeyArr:
                    if c == 'J':
                        KeyArr.append('I')
                    else:
                        KeyArr.append(c)

            is_I = "I" in KeyArr

            for i in range(65, 91):
                if chr(i) not in KeyArr:
                    # We want I in the KeyArr not J

                    if i == 73 and not is_I:
                        KeyArr.append("I")
                        is_I = True
                    elif i == 73 or i == 74 and is_I:
                        pass
                    else:
                        KeyArr.append(chr(i))

            index = 0
            for i in range(0, 5):
                for j in range(0, 5):
                    matrix[i][j] = KeyArr[index]
                    index += 1

            return matrix

        def convertCipherTextToDiagraphs(cipherText):
            # Remove any spaces
            cipherText = cipherText.replace(" ", "")
            # Split cipherText into diagraphs
            diagraphs = [cipherText[i:i + 2] for i in range(0, len(cipherText), 2)]

            return diagraphs

        def indexLocator(char, cipherKeyMatrix):
            indexOfChar = []

            # convert the character value from J to I
            if char == "J":
                char = "I"

            for i, j in enumerate(cipherKeyMatrix):

                # j refers to inside matrix
                for a, b in enumerate(j):

                    if char == b:
                        indexOfChar.append(i)
                        indexOfChar.append(a)
                        return indexOfChar

        def decryption(cipherText, key, xSpace):
            # Generate Key Matrix
            keyMatrix = generateKeyMatrix(key)

            # Decrypts using playfair algorithm
            plainText = ""
            diagraphs = convertCipherTextToDiagraphs(cipherText)

            for digraph in diagraphs:
                node1 = indexLocator(digraph[0], keyMatrix)
                node2 = indexLocator(digraph[1], keyMatrix)

                if node1[1] == node2[1]:
                    i1 = (node1[0] - 1) % 5
                    j1 = node1[1]

                    i2 = (node2[0] - 1) % 5
                    j2 = node2[1]
                    plainText += keyMatrix[i1][j1]
                    plainText += keyMatrix[i2][j2]

                elif node1[0] == node2[0]:
                    i1 = node1[0]
                    j1 = (node1[1] - 1) % 5

                    i2 = node2[0]
                    j2 = (node2[1] - 1) % 5
                    plainText += keyMatrix[i1][j1]
                    plainText += keyMatrix[i2][j2]

                else:
                    i1 = node1[0]
                    j1 = node2[1]

                    i2 = node2[0]
                    j2 = node1[1]
                    plainText += keyMatrix[i1][j1]
                    plainText += keyMatrix[i2][j2]

            # Remove any extra X's added during encryption
            plainText = plainText.replace("X", "")

            temp_plain = []
            temp_plain.extend(plainText)
            for tuple in xSpace:
                # adds all the original Xs and spaces back to the text
                temp_plain.insert(tuple[1], tuple[0])

            result = "".join(temp_plain)

            return result

        # Call decryption function and return the result
        result = decryption(cipherText.upper(), key.upper(), xSpace)
        result = "".join(result)

        self.__decrypted_text .append(result.upper())  # make decrypted_text private

    def Decrypt_Substitution(self, encrypted_text):
        encrypt_map = encrypted_text[1]  # takes the encrypt_map from the encryption method
        ciphertext = encrypted_text[0]  # takes the ciphertext from the encryption method
        cipher_type = encrypted_text[2]  # takes the cipher_type from the massage class
        xSpace = encrypted_text[3] # takes the spaces from the plaintext

        plaintext = []
        for letter in ciphertext:
            # adds the spaces
            if letter == " ":
                plaintext.append(" ")
            else:
                for key, value in encrypt_map.items():
                    # takes the letter corresponded with the new value and appends it to a list
                    if value == letter:
                        plaintext.append(key)

        result = ''.join(plaintext)


        if cipher_type != "Product_cipher":
            # if it's not a product cipher calling the method
            # it doesn't return it and stores the results instead
            self.__decrypted_text .append(result)
        else:
            return result

    def Decrypt_Transposition(self, encrypted_text):
        xSpace = encrypted_text[3]
        plaintext = encrypted_text[0]
        cipher = encrypted_text[1]
        cipher_type = encrypted_text[2]

        def decrypt(cipher, ciphertext):
            result = inverse_encrypt(inverse_key(cipher), ciphertext).strip().replace("X", "")
            return result

        def inverse_encrypt(cipher, plaintext):
            # Convert the plaintext to all uppercase and remove any spaces
            plaintext = "".join(plaintext.split(" ")).upper()
            # Make a string out of plaintext list with spaces and all uppercase

            # Pad the plaintext with "X" characters so its length is a multiple of the cipher length
            for pad in range(0, len(plaintext) % len(cipher) * -1 % len(cipher)):
                plaintext += "X"

            ciphertext = ""  # Initialize the ciphertext string

            # Iterate over the plaintext in blocks the size of the cipher and apply the substitution cipher
            for offset in range(0, len(plaintext), len(cipher)):
                # Apply the cipher by selecting each element of the cipher list and adding it to the offset
                for element in [a - 1 for a in cipher]:
                    ciphertext += plaintext[offset + element]  # Append the encrypted character to the ciphertext
                ciphertext += " "  # Add a space to separate each block of the ciphertext

            return ciphertext[:-1]  # Return the ciphertext string with the final space removed

        def inverse_key(cipher):
            inverse = []
            # Iterate over the range of positions in the cipher, starting from the minimum to the maximum
            for position in range(min(cipher), max(cipher) + 1, 1):
                # Find the index of the current position in the cipher and append it to the inverse list
                inverse.append(cipher.index(position) + 1)
            return inverse  # Return the inverse cipher list

        result = decrypt(cipher, plaintext)  # Decrypt the ciphertext using the given cipher
        temp_plain = []
        temp_plain.extend(result)
        for letter in temp_plain:
            if letter == " ":
                temp_plain.pop(temp_plain.index(letter))
        # Remove any spaces from the decrypted plaintext and store it in temp_plain

        for tuple in xSpace:
            # Iterate over each tuple of (character, position) pairs representing the original Xs and spaces in the plaintext
            temp_plain.insert(tuple[1], tuple[0])  # Insert the character back into temp_plain at its original position
        result = temp_plain  # Store the updated temp_plain in result
        result = (''.join(result)).upper()  # Convert result to a string and make it all uppercase

        if cipher_type != "Product_cipher":
            self.__decrypted_text.append(
                result)  # If the cipher type is not a product cipher, append the result to the decrypted text list
        else:
            return result  # Otherwise, return the result

    def Decrypt_Product(self, encrypted_text):

        d1 = [encrypted_text[0], encrypted_text[1][1], encrypted_text[2], encrypted_text[3]]

        # Decrypt the first pass using a transposition cipher and store the result in pass_1
        pass_1 = self.Decrypt_Transposition(d1)

        # Convert pass_1 to lowercase
        pass_1 = pass_1.lower()

        # Create a list of the first, first letter of the second word, and third letters of the encrypted text,
        # and use pass_1 as the first element
        d2 = [pass_1, encrypted_text[1][0], encrypted_text[2], encrypted_text[3]]

        # Decrypt the second pass using a substitution cipher and store the result in pass_2
        pass_2 = self.Decrypt_Substitution(d2)

        # Store pass_2 in result
        result = pass_2


        # Append the result to the decrypted text list
        self.__decrypted_text .append(result)

    def Decrypt_RSA(self, encrypted_text):

        encrypted = encrypted_text[1][0]
        d = encrypted_text[1][1]
        n = encrypted_text[1][2]

        # Decrypt the message using the private key (d, n)
        decrypted = [pow(b, d, n) for b in encrypted]

        # Convert bytes back to string
        decrypted_string = bytes(decrypted).decode()

        self.__decrypted_text .append(decrypted_string)

    def displayText(self):
        counter = 0
        num = 1

        if self.__encrypted_strings_display != []:
            print("DECRYPTED FROM ENCRYPTED TEXT")
            print("--------------------------------")
            for list in enumerate(self.__encrypted_strings_display):
                print(f"{num}. Decrypted Text: {self.__decrypted_text [counter]}")
                counter += 1
                num += 1
        else:
            print('\033[1m' + '\033[91m' + f"\nNO OPERATION TOOK PLACE\n" + '\033[0m')


if __name__ == "__main__":

    plaintextMsg = plaintextMsg()
    ciphertext = ciphertextMsg(plaintextMsg)

    while True:

        user_input = str(
            input('Please enter your string that you would like to encrypt, type STOP when you are done\n> ')).lower()

        cryptography = random.choice(
            ["Playfair_cipher", "Caesar_cipher", "Product_cipher", "RSA", "Substitution_cipher",
             "Transposition_Cipher"])

        

        if user_input == "stop" or "stop" in user_input:
            break
        elif user_input == "":
            pass
        else:
            plaintextMsg.storeString(user_input, cryptography)

        # If the selected encryption is Substitution_cipher
        if cryptography == "Substitution_cipher":
            # Encrypt the input string using Substitution_cipher
            encrypted = plaintextMsg.Substitution_cipher(user_input)
            # Decrypt the encrypted string and store it in ciphertext object
            ciphertext.Decrypt_Substitution(encrypted)
            # Store the encrypted string in ciphertext object
            ciphertext.Store(encrypted)
            print("Encrypting...")

        # If the selected encryption is Playfair_cipher
        elif cryptography == "Playfair_cipher":
            try:
                if len(user_input.strip()) < 25:
                    # Check if the input string contains only alphabets and no numbers or symbols
                    if user_input is not ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
                        # Choose a random key for Playfair_cipher
                        key = random.choice(
                            ["python", "jumble", "easy", "difficult", "answer", "xylophone", "Al", "Mohammed", "Ash",
                             "Yousif"])
                        # Encrypt the input string using Playfair_cipher with the chosen key
                        encrypted = plaintextMsg.Playfair_cipher(user_input, key)
                        # Decrypt the encrypted string and store it in ciphertext object
                        ciphertext.Decrypt_Playfair(encrypted)
                        # Store the encrypted string in ciphertext object
                        ciphertext.Store(encrypted)
                        print("Encrypting ...")
                    else:
                        raise TypeError
                else:
                    raise MemoryError
            except MemoryError as Error:
                print(
                    '\033[1m' + '\033[91m' + f"\nExceeded Character Limit (>25) for Playfair Cipher, Try Again!!!\n" + '\033[0m')
            except TypeError as Error:
                print(
                    '\033[1m' + '\033[91m' + f"\nPlayfair Cipher dose not except Numbers and symbols, Try Again!!!\n" + '\033[0m')

        # If the selected encryption is Caesar_cipher
        elif cryptography == "Caesar_cipher":
            try:
                # Encrypt the input string using Caesar_cipher
                encrypted = plaintextMsg.Caesar_cipher(user_input)
                # Decrypt the encrypted string and store it in ciphertext object
                ciphertext.Decrypt_Caesar(encrypted)
                # Store the encrypted string in ciphertext object
                ciphertext.Store(encrypted)
                print("Encrypting ...")
            except KeyError:
                print(
                    '\033[1m' + '\033[91m' + f"\nCaesar Cipher dose not except Numbers and symbols, Try Again!!!\n" + '\033[0m')

        # If the selected encryption is Transposition_Cipher
        elif cryptography == "Transposition_Cipher":
            encrypted = plaintextMsg.Transposition_cipher(user_input)
            ciphertext.Decrypt_Transposition(encrypted)
            ciphertext.Store(encrypted)
            print("Encrypting...")


        elif cryptography == "Product_cipher":
            encrypted = plaintextMsg.Product_cipher(user_input)
            ciphertext.Store(encrypted)
            ciphertext.Decrypt_Product(encrypted)
            print("Encrypting...")


        elif cryptography == "RSA":
            encrypted = plaintextMsg.Rsa_cipher(user_input)
            ciphertext.Decrypt_RSA(encrypted)
            ciphertext.Store(encrypted)
            print("Encrypting...")

        pass

print("")
plaintextMsg.displayText() #Display Encrypted Text
ciphertext.displayText() #Display Decrypted Text

"""END OF PROGRAM"""
