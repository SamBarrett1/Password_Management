"""Run tests"""

import hashlib
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import os
import rsa
import random
import csv
DES_BLOCK_SIZE = 16
FILENAME = "password.csv"
FILENAME_BIN = "password_bin.txt"

def main():

    # # sentinel for while loop
    # get_input = True

    # # DES requires an 8 byte length key, this key can be called the salt
    # des_key = get_random_bytes(8)

    # # get user password with length 16 or less
    # print("Enter password")
    # password = str(input(">>> "))
    # while get_input:
    #     if len(password) <= 16:
    #         get_input = False
    #         break
    #     else:
    #         print("Password must be 16 characters or less")
    #         print("Enter password")
    #         password = str(input(">>> "))

    # print()
    # # Display the random 8 bytes of salt
    # print(f"The random 8 byte DES key for salt is: {des_key}")
    
    # # Now encode the password into byte format
    # encode_password = password.encode("utf-8")
    
    # # now pad the password if < 16 bytes
    # pad_password = pad(encode_password, DES_BLOCK_SIZE)
    # print()

    # # Now encrypt with DES
    # des = DES.new(des_key, DES.MODE_ECB)
    # DES_encrypted_password = des.encrypt(pad_password)
    # print(f"The Encrypted password is: {DES_encrypted_password}")
    # print()

    # decrypted_password = des.decrypt(DES_encrypted_password)
    # print(f"The Decrypted password is: {decrypted_password}")
    # print()

    # # Now unpad the decrypted password to see it decrypted
    # unpad_decrypted = unpad(decrypted_password, 16)
    # print(f"The Unpadded Decrypted password is: {unpad_decrypted}")
    # print()

#------------------Decrypt tests---------------------

    # THIS WORKS FOR CHECKING THE PASSWORD

    # Stored info (imagine this could be retrieved from the password file indexed by a set User_id(which can be email, or id_number, user_name etc))
    # Random DES key = b'\x8cX(\x98="\xdaG'
    # Password cipher = b'\x9a\xd7\x00\xaen\xec\x1e\xe9\x87\xd5o\x14\x1ex\xdf\x8a'
    # Original password to match = rd12dhflkad%6(.3

    # # get user password
    # print("Enter password")
    # password = str(input(">>> "))
    # # create b' ' format just for comparing to decrypted password
    # entered_password = "b'"+password+"'"

    # # Use user id to index the password file and locate this info
    # # create a function to search a file for this
    # des_key = b'Q\xc3\x9fd\xcf-\xba\n'
    # DES_encrypted_password = b'np\xb4\xb1\xf5\xb4\xd8nf9\xd6\x978}\xfbu'

    # des = DES.new(des_key, DES.MODE_ECB)
    # decrypted_password = des.decrypt(DES_encrypted_password)
    # print(decrypted_password)
    # print(type(decrypted_password))
    
    # # unpad and convert the decrypted password to a string before comparing to the user's password
    # unpad_decrypted = unpad(decrypted_password, 16)
    # str_unpad_decrypted = str(unpad_decrypted)

    # # create a function to verify the password like this, return true or false to the application
    # if entered_password == str_unpad_decrypted:
    #     print("Access granted")
    # else:
    #     print("issue")

#-----------------------------CSV read test----------------------
    
#     # Get User ID
#     print("Enter User ID: ")
#     id = str(input(">>> "))
#     get_id = True
#     while get_id:
#         if len(id) > 3 and len(id) < 5:
#             get_id = False
#             break
#         else:
#             print("Invalid User ID - Enter User ID: ")
#             id = str(input(">>> "))

#     # Get User Password
#     print("Enter password to log in")
#     password = str(input(">>> "))
#     get_input = True
#     while get_input:
#         if len(password) <= 16:
#             get_input = False
#             break
#         else:
#             print("Password must be 16 characters or less")
#             print("Enter password")
#             password = str(input(">>> "))

# # BUG HERE: THE FILE IS READING THE BYTE STRING AS A STRING AND GIVING IT 23BYTE LENGTH INSTEAD OF DES 16 BYTE
# # THIS NEED TO BE ADDRESSED BY DECODING THE BYTE STRING BEFORE IT IS WRITTEN TO FILE AND THE RECODING TO BYTE STRING
# # ONCE IT IS READ. BUT THERE ARE DECODE ERRORS I'M GETTING WHEN TRYING TO DO THIS THAT I CAN'T RESOLVE YET 

#     with open(FILENAME, newline='', encoding='ascii') as password_file:
#         reader = csv.reader(password_file, delimiter=',', quoting=csv.QUOTE_NONE)
#         for row in reader:
#             if row[0] == id:
#                 des_key = row[1]
#                 print(f"This is des-key {des_key}")
#                 print(f"This is des-key length {type(des_key)}")
#                 dec_encoded = des_key.encode('utf-8')
#                 print(f"This is re-encoded {dec_encoded}")
#                 print(f"This is dec_encoded type {type(dec_encoded)}")
#                 print(f"This is dec_encoded len(): {len(dec_encoded)}")
#                 DES_encrypted_password = row[2]
#                 print(f"This is DES_encrypted_password {DES_encrypted_password}")
#                 print(f"This is the current record: {row}")

#     # get password cipher with stored salt and current user password tp compare with stored password cipher
#     # Now encode the password into byte format for the C code in DES algorithm
#     encoded_password = password.encode("utf-8")
    
#     # now pad the password if < 16 bytes, so it is a 16 byte block for DES algorithm
#     padded_password = pad(encoded_password, DES_BLOCK_SIZE)
#     print(len(padded_password))

#     # Send stored des_key and current user's password as padded_password with utf-8 encoding to DES algorithm for encryption
#     Current_DES_encrypted_password = encrypt_DES(padded_password, des_key)

#     # des = DES.new(des_key, DES.MODE_ECB)
#     # decrypted_password = des.decrypt(DES_encrypted_password)
#     # print(decrypted_password)
#     # print(type(decrypted_password))
    
#     # unpad and convert the decrypted password to a string before comparing to the user's password
#     # unpad_decrypted = unpad(decrypted_password, 16)
#     # str_unpad_decrypted = str(unpad_decrypted)

#     # Validate current passwoerd cipher with stored password cipher to determine access
#     if Current_DES_encrypted_password == DES_encrypted_password:
#         print("Access granted")
#     else:
#         print("issue")

#---------TEST GET_RAND_BYTES() WITH ENCODE AND DECODE----------------------
    # Windows uses 'Extended ASCII' which is an 8-bit version rather than 7-bit
    # 8-bit binary code - A number of standards extend ASCII to eight bits by adding a further 128 characters
    # Must decode with windows binary code "windows-1252" =  .decode("iso-8859-1") or .encode("iso-8859-1")

    rbytes = Random.get_random_bytes(8)
    # rbytes = random.randbytes(8)
    # rbytes = get_os_random_bytes(8)
    print(rbytes)
    print(type(rbytes))
    print(len(rbytes))
    decb = rbytes.decode("iso-8859-1")
    print(f"This is origina rbytes: {rbytes}")
    print(f"This is decoded rbytes: {decb}")
    rdecb = decb.encode("iso-8859-1")
    print(f"This is recoded rbytes: {rdecb}")
    password = Random.get_random_bytes(8)
    print(f"This is password {password}")
    # password_e = password.encode("iso-8859-1")
    # print(f"This is password_e {password_e}")
    # print(f"This is password_e len {len(password_e)}")
    password_d = password.decode("iso-8859-1")
    print(f"This is password_d {password_d}")
    print(f"This is password_d len {len(password_d)}")
    password_re = password_d.encode("iso-8859-1")
    print(f"This is password_re {password_re}")
    print(f"This is password_re len {len(password_re)}")


    # s = "Hello"
    # bs = s.encode('utf-8')
    # print(s)
    # print(bs)
    # print(bs.decode())



#----------------------------------------------------------------

def get_salt():
    # generate random salt between 0 - 1,000,000
    new_salt = random.randint(10000000, 90000000)
    return new_salt

# def pad(text):
#     n = len(text) % 8
#     return text + (b' ' * n)

def get_random_bytes(byte_count):
    # return a length of radom bytes, takes an integer
    rand_bytes = random.randbytes(byte_count)
    return rand_bytes

def get_os_random_bytes(byte_count):
    # return a length of radom bytes, takes an integer
    # rand_bytes = random.randbytes(byte_count)
    os_rand_bytes = os.urandom(byte_count)
    return os_rand_bytes

def encrypt_DES(password, salt):
    # Encrypt password with DES, parameters require bytes type
    des = DES.new(salt, DES.MODE_ECB)
    DES_encrypted_password = des.encrypt(password)
    return DES_encrypted_password

main()