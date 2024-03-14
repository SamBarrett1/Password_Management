"""
/* ===================================================================
 *
 * Copyright (c) 2024, Samuel Barrett
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
"""

"""
Password Management System
- Using 1977 DES symmetric block encryption from Pycryptodome library
- DES requires a 56bit key from an 8 bytes block (64bit)
- Password must be, or be buffered into a 16 bytes block (128bit)
- Note: Windows OS uses extended 8-bit ASCII with encoding="iso-8859-1"

CURRENT ISSUES:
- If password_DES.txt exists and is empty the program will throw an error
  delete the empty password_DES.txt before running the program
- Due to the format of the file sometimes printing the password_DES.txt
  file prints out of allignment, or incompletely
- View the password_DES.txt file with with Windows Notepad to see clearly 

requirements.txt:
chardet==5.2.0
pyasn1==0.5.1
pycryptodome==3.20.0
rsa==4.9
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import os
KEY_SIZE = 8
BLOCK_SIZE = 16
FILENAME = "password_DES.txt"
__author__ = 'Samuel Barrett'


def main():

    menu = ('Select from the following options:\n'
            '1: Register New Account\n'
            '2: Sign In\n'
            '3: Display Password File \n'
            '4: Enter message to encrypt \n'
            '0: Log Out \n')
    
    print(menu)
    choice = str(input(">>> "))

    while choice != "0":
        if choice == "1":
            # create record for password file
            record = []

            # DES requires an 8 byte length key, this key can be called the salt
            os_des_key = Random.get_random_bytes(KEY_SIZE)

            # get user password with length 16 or less
            print("Enter password")
            password = str(input(">>> "))
            get_input = True
            while get_input:
                if len(password) <= 16:
                    get_input = False
                    break
                else:
                    print("Password must be 16 characters or less")
                    print("Enter password")
                    password = str(input(">>> "))

            # Now encode the password into byte format for the C code in DES algorithm
            encoded_password = password.encode("iso-8859-1")
            
            # now pad the password if < 16 bytes, so it is a 16 byte block for DES algorithm
            padded_password = pad(encoded_password, BLOCK_SIZE)
            print()

            # Send des_key and padded_password to DES algorithm for encryption
            DES_encrypted_password = encrypt_DES(padded_password, os_des_key)

            # Get user_id, check if file exists first (if empty file exists it will throw an error)
            if os.path.exists(FILENAME):
                last_user_id = highest_user_id(FILENAME)
                user_id = last_user_id + 1
                str(user_id)
            else:
                user_id = 1000

            # Populate record list and send to file in decoded format to remove the byte mode b'...'
            # will need to be re-encoded with .encode("iso-8859-1") before pass to DES algorithm later
            decoded_os_des_key = os_des_key.decode("iso-8859-1")
            decoded_DES_encrypted_password = DES_encrypted_password.decode("iso-8859-1")
            record.append(str(user_id))
            record.append(decoded_os_des_key)
            record.append(decoded_DES_encrypted_password)

            # write to txt file
            with open(FILENAME, mode='a', newline='', encoding="iso-8859-1") as password_file:
                password_file.write(record[0] + "," + record[1] + "," + record[2] + "\n")

            # Display user details
            print(f"Your new User ID number is:     {user_id}")
            print(f"Your password is:               {password}")
            print(f"Your Salt is:                   {os_des_key}")
            print(f"Your DES encrypted password is: {DES_encrypted_password}")
            print("\n")

            # Print options list again
            print(menu)
            choice = str(input(">>> "))

        elif choice == "2":
            # Validate user   
            
            # Get User ID
            print("Enter User ID: ")
            id = str(input(">>> "))
            get_id = True
            while get_id:
                if len(id) > 3 and len(id) < 5:
                    get_id = False
                    break
                else:
                    print("Invalid User ID - Enter User ID: ")

            # Get User Password
            print("Enter password to log in")
            password = str(input(">>> "))
            get_input = True
            while get_input:
                if len(password) <= 16:
                    get_input = False
                    break
                else:
                    print("Password must be 16 characters or less")
                    print("Enter password")
                    password = str(input(">>> "))
            
            # If user is registered try password validation
            if is_user_registered(FILENAME, id):
                # validate_password(password)
                if validate_password(FILENAME, id, password):
                    print("Access granted")
                    break
                else:
                    print("Incorrect password")
            else:
                print("User_id does not exist")

        elif choice == "3":
            print_file(FILENAME)
            print()
            # Print options list again
            print(menu)
            choice = str(input(">>> "))
            
        else:
            print("Invalid menu choice")
            print("\n")
            print(menu)
            choice = str(input(">>> "))

    # End of main() program
    print("Thank-you")

def to_raw(string):
    return fr"{string}"

def encrypt_DES(password, salt):
    # Encrypt password with DES, parameters require bytes type
    des = DES.new(salt, DES.MODE_ECB)
    DES_encrypted_password = des.encrypt(password)
    return DES_encrypted_password

def validate_password(filename, user_id, password):
    # read password file (for Windows read with encoding="iso-8859-1"),
    # re-encode stored salt with current password and match stored DES password cipher-txt to validate
    with open(filename, encoding="iso-8859-1") as file:
        # loop to read file from the end with -1 
        for line in (file.readlines()):
            user_record_list = line.strip().split(",")
            if user_id == user_record_list[0]:
                # select stored salt and encode as bytes(for Windows use: "iso-8859-1")
                bytes_salt = user_record_list[1].encode("iso-8859-1")
                # select stored decoded DES password ready for comparison
                stored_DES_password = user_record_list[2].encode("iso-8859-1")
                # convert current user password input to bytes (for Windows use: "iso-8859-1")
                bytes_password = password.encode("iso-8859-1")
                # now pad the password if < 16 bytes, so it is a 16 byte block for DES algorithm
                padded_password = pad(bytes_password, BLOCK_SIZE)
                # get secure hash from current password and stored salt
                new_DES_encrypted_password = encrypt_DES(padded_password, bytes_salt)
                # check if hash matches with stored hash
                if stored_DES_password == new_DES_encrypted_password:
                    return True
    return False

def is_user_registered(filename, user_id):
    # read password file, return true if user_id is found
    with open(filename, encoding="iso-8859-1") as file:
        # loop to read file from the end with -1 
        for line in file:
            user_record_list = line.strip().split(",")
            stored_user_id = user_record_list[0]
            if user_id == stored_user_id:
                return True
    return False

def highest_user_id(filename):
    # read last line of file to return current highest registered user_id
    with open(filename, encoding="iso-8859-1") as file:
        # loop to read file from the end with -1 
        for line in (file.readlines() [-1:]):
            # print(line, end ='')
            # strip and split the line by "," to create a list
            user_record_list = line.strip().split(",")
            # index the list item containing the user_id and convert to an int
            user_id = int(user_record_list[0])
            return user_id

def decrypt_DES(DES_encrypted_password, salt):
    # Decrypt DES encrypted password
    des = DES.new(b'salt', DES.MODE_ECB)
    decrypted_password = des.decrypt(DES_encrypted_password)
    return decrypted_password


def get_random_bytes(byte_count):
    # return a length of radom bytes, takes an integer
    # rand_bytes = random.randbytes(byte_count)
    rand_bytes = Random.get_random_bytes(byte_count)
    return rand_bytes

def get_os_random_bytes(byte_count):
    # return a length of radom bytes, takes an integer
    # rand_bytes = random.randbytes(byte_count)
    os_rand_bytes = os.urandom(byte_count)
    return os_rand_bytes

def print_file(filename):
    # print full file to console
    try:
        with open(filename, 'r', encoding="iso-8859-1") as file:
            # Read the lines of the file
            file_lines = file.readlines()
            # Print each line
            print(f"The {filename} contains:")
            for line in file_lines:
                print(line.strip())
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()