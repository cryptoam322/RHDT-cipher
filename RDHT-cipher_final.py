"""
The python code here implements a cipher that I am calling Randomness Hardened Double Transposition(RHDT)

---LICENSE---
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
Copyright cryptoam 2023
"""
import secrets

def main():
    print("This is the RHDT tool")
    print("All inputs must be uppercase letters with no symbols or spaces")
    print("Program is liable to crash or malfunction if invalid input is provided")
    exit_enable=False
    while exit_enable==False:
        mode=input("Encrypt(E) or Decrypt(D) or Exit(EXIT)?\n--->")
        if mode=="E":
            encrypt_mode()
        elif mode=="D":
            decrypt_mode()
        elif mode=="EXIT":
            exit_enable=True
        else:
            print("Invalid entry, try again")
    input("Press enter to end program")

def encrypt_mode():
    print("In encryption mode now")
    plaintext=input("What is the plaintext?\n--->")
    key1=input("What is the first key?\n--->")
    key2=input("What is the second key?\n--->")
    print("Plaintext is: "+plaintext)
    print("Key 1 is: "+key1)
    print("Key 2 is: "+key2)
    preprocessed_plaintext=preprocess_forward(plaintext)
    ciphertext=double_transpose_encrypt(preprocessed_plaintext, key1, key2)
    print("Ciphertext is: "+ciphertext)

def decrypt_mode():
    print("In decryption mode now")
    ciphertext=input("What is the ciphertext?\n--->")
    key1=input("What is the first key?\n--->")
    key2=input("What is the second key?\n--->")
    print("Ciphertext is: "+ciphertext)
    print("Key 1 is: "+key1)
    print("Key 2 is: "+key2)
    preprocessed_plaintext=double_transpose_decrypt(ciphertext, key1, key2)
    plaintext=preprocess_backward(preprocessed_plaintext)
    print("Plaintext is: "+plaintext)

def preprocess_forward(plaintext):
    # Convert the plaintext into a stream of 0-25
    plaintext_stream=[]
    for char in plaintext:
        num=ord(char)-ord("A")
        plaintext_stream.append(num)
    # Obtain an actually random(read: unpredictable to adversary) stream of 0-25
    random_stream=[]
    for i in range(len(plaintext_stream)):
        random_num=secrets.randbelow(26)
        random_stream.append(random_num)
    # Now start crossing the streams
    # :P
    preprocessed_stream=[]
    for i in range(len(plaintext_stream)):
        char_num=plaintext_stream[i]
        random_num=random_stream[i]
        a=((2*char_num)+random_num)%26
        b=(char_num+random_num)%26
        preprocessed_stream.append(a)
        preprocessed_stream.append(b)
    # Convert the numbers in the preprocessed stream back into letters
    preprocessed_plaintext=""
    for num in preprocessed_stream:
        char=chr(num+ord("A"))
        preprocessed_plaintext=preprocessed_plaintext+char
    return(preprocessed_plaintext)

def preprocess_backward(preprocessed_plaintext):
    # Convert the preprocessed plaintext into a stream of 0-25
    number_stream=[]
    for char in preprocessed_plaintext:
        num=ord(char)-ord("A")
        number_stream.append(num)
    # Convert the stream of numbers into a stream of tuples (a,b)
    tuple_stream=[]
    for i in range(0, len(number_stream), 2):
        tuple_stream.append((number_stream[i],number_stream[i+1]))
    # Now we process each tuple to recover the plaintext number
    plaintext_stream=[]
    for tup in tuple_stream:
        a=tup[0]
        b=tup[1]
        c=a-b
        if c<0:
            plaintext_num=c+26
        else:
            plaintext_num=c
        plaintext_stream.append(plaintext_num)
    # Finally recover the plaintext from the stream of 0-25
    plaintext=""
    for num in plaintext_stream:
        char=chr(num+ord("A"))
        plaintext=plaintext+char
    return(plaintext)

def transpose_encrypt(plaintext, key):
    columns = len(key)
    rows = (len(plaintext) + columns - 1) // columns
    grid = []
    # Create a grid for the plaintext
    for i in range(rows):
        a = []
        for j in range(columns):
            a.append("")
        grid.append(a)
    # Fill the grid with the plaintext
    index = 0
    for row in range(rows):
        for col in range(columns):
            if index < len(plaintext):
                grid[row][col] = plaintext[index]
                index=index+1
            else:
                grid[row][col]="$"
    # Sort the columns based on the key
    sorted_columns = [col for col in range(columns)]
    sorted_columns.sort(key=lambda x: key[x])
    # Create a new grid
    new_grid=[]
    for i in range(rows):
        a = []
        for j in range(columns):
            a.append("")
        new_grid.append(a)
    # Fill in the new grid according the the sorted collum
    for row in range(rows):
        for col in range(columns):
            new_grid[row][col]=grid[row][sorted_columns[col]]
    # Extract the ciphertext from the new grid using the sorted columns 
    ciphertext = ""
    for row in range(rows):
        for col in range(columns):
            char=new_grid[row][col]
            if char=="$":
                pass
            else:
                ciphertext=ciphertext+char
    return (ciphertext)

def transpose_decrypt(ciphertext, key):
    columns = len(key)
    rows = (len(ciphertext) + columns - 1) // columns
    grid = []
    # Create a grid for the ciphertext
    for i in range(rows):
        a = []
        for j in range(columns):
            a.append("")
        grid.append(a)
    # Sort the columns based on the key
    sorted_columns = [col for col in range(columns)]
    sorted_columns.sort(key=lambda x: key[x])
    # Fill in the grid for the full rows
    index = 0
    for row in range(rows-1):
        for col in range(columns):
            if index < len(ciphertext):
                grid[row][col] = ciphertext[index]
                index=index+1
    # We need to be careful now
    # The last row is not garunteed to be full, must now perform a check
    a=(len(ciphertext)%columns)
    if a==0:
        # We do not need to worry, we can just carry on
        # The length of the ciphertext is a multiple of the key, there will not be mismatched column lengths
        for col in range(columns):
            grid[rows-1][col]=ciphertext[index]
            index=index+1
    else:
        # Turns out we do need to worry, column lengths will be mismatched
        for col in range(columns):
            current_collum_index=sorted_columns[col]
            if current_collum_index>=a:
                #We are writing to a column that does not have a character, pad it instead
                grid[rows-1][col]="$"
            else:
                grid[rows-1][col]=ciphertext[index]
                index=index+1
    new_grid=[]
    for i in range(rows):
        a = []
        for j in range(columns):
            a.append("")
        new_grid.append(a)
    # Copy characters over to the new grid but this time with the collumns in the right place
    index=0
    for col in sorted_columns:
        for row in range(rows):
            char=grid[row][index]
            new_grid[row][col]=char
        index=index+1
    # Extract the plaintext from the grid
    plaintext=""
    for row in range(rows):
        for col in range(columns):
            char=new_grid[row][col]
            if char=="$":
                pass    #padding, ignore and move on to the next one
            else:
                plaintext=plaintext+char
    return(plaintext)

def double_transpose_encrypt(plaintext, key1, key2):
    partial_encrypt=transpose_encrypt(plaintext, key1)
    ciphertext=transpose_encrypt(partial_encrypt, key2)
    return(ciphertext)

def double_transpose_decrypt(ciphertext, key1, key2):
    partial_decrypt=transpose_decrypt(ciphertext, key2)
    plaintext=transpose_decrypt(partial_decrypt, key1)
    return(plaintext)

if __name__=="__main__":
    main()