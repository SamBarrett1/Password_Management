"""
Password Management System
- Using SHA256 hash function from the Hashlib library

requirements.txt:
chardet==5.2.0
pyasn1==0.5.1
pycryptodome==3.20.0
rsa==4.9
"""

import hashlib
import random
import os
FILENAME= "password.txt"
__author__ = 'Samuel Barrett'

def main():

    menu = ('Select from the following options:\n'
            '1: Register New Account\n'
            '2: Sign In\n'
            '3: Display Password File \n'
            '0: Log Out \n')
    
    print(menu)
    choice = str(input(">>> "))

    while choice != "0":

        if choice == "1":
            # create record for password file
            record = []
            
            # Create large random Salt as a string
            salt = str(get_salt())

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

            # convert password and salt to bytes for the hash algorithm
            bytes_password = password.encode('utf-8')
            bytes_salt = salt.encode('utf-8')
            
            # Create hash digest of salt and password
            secure_hash = get_secure_hash(bytes_password, bytes_salt)

            # Get user_id, check if file exists first (if empty file exists it will throw an error)
            if os.path.exists('password.txt'):
                last_user_id = highest_user_id(FILENAME)
                user_id = last_user_id + 1
                str(user_id)
            else:
                user_id = 1000

            # Populate record list with salt before it is converted to bytes, this will need to be
            # re-encoded with .encode("utf-8") before passing it to the hash function for validation
            record.append(str(user_id))
            record.append(salt)
            record.append(secure_hash)

            # # write to txt file
            with open(FILENAME, mode='a', newline='') as password_file:
                password_file.write(record[0] + "," + record[1] + "," + record[2] + "\n")

            # Display user details
            print(f"Your new User ID number is:     {user_id}")
            print(f"Your password is:               {password}")
            print(f"Your Salt is:                   {salt}")
            print(f"Your SHA256 secure_hash hex-digest is: {secure_hash}")
            print("\n")

            # Print options list again
            print(menu)
            choice = str(input(">>> "))

        elif choice == "2":
            # Validate user
            get_id = True
            while get_id:
                # Get User ID
                print("Enter User ID: ")
                id = str(input(">>> "))
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

def validate_password(filename, user_id, password):
    # read password file, rehash stored salt with current password and match hash to validate
    with open(filename) as file:
        # loop to read file from the end with -1 
        for line in (file.readlines()):
            user_record_list = line.strip().split(",")
            if user_id == user_record_list[0]:
                # select stored salt and encode as bytes
                bytes_salt = user_record_list[1].encode('utf-8')
                # select stored secure_hash ready for comparison
                stored_secure_hash = user_record_list[2]
                # convert current user password input to bytes
                bytes_password = password.encode('utf-8')
                # get secure hash from current password and stored salt
                secure_hash = get_secure_hash(bytes_password, bytes_salt)
                # check if hash matches with stored hash
                if stored_secure_hash == secure_hash:
                    return True
    return False

def is_user_registered(filename, user_id):
    # read password file, return true if user_id is found
    with open(filename) as file:
        # loop to read file from the end with -1 
        for line in file:
            user_record_list = line.strip().split(",")
            stored_user_id = user_record_list[0]
            if user_id == stored_user_id:
                return True
    return False

def get_secure_hash(bytes_password, bytes_salt):
    # get secure hash with byte form of password and salt
    h = hashlib.new('sha256')
    h.update(bytes_password)
    h.update(bytes_salt)
    secure_hash = h.hexdigest()
    return secure_hash

def get_salt():
    # generate random salt between 2 large integers
    new_salt = random.randint(1000000000000000, 1000000000000000000)
    return new_salt

def highest_user_id(filename):
    # read last line of file to return current highest registered user_id
    with open(filename) as file:
        # loop to read file from the end with -1 
        for line in (file.readlines() [-1:]):
            # print(line, end ='')
            # strip and split the line by "," to create a list
            user_record_list = line.strip().split(",")
            # index the list item containing the user_id and convert to an int
            user_id = int(user_record_list[0])
            return user_id
        
def print_file(filename):
    # print full file to console
    try:
        with open(filename, 'r') as file:
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