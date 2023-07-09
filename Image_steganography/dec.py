from PIL import Image
import os
import hashlib
from Crypto.Cipher import AES

def decrypt_file(key, inptut_filename, output_filename=None, chunksize=24*1024):
    """Decrypts a file using AES (CBC mode) with the given key. Parameters
    inptut_filename: Input file to decrypt
    output_filename: Output file. If None, use inptut_filename without .enc extension
    chunksize: Chunk size for decryption
    """
    if not output_filename:
        output_filename = os.path.splitext(inptut_filename)[0]

    with open(inptut_filename, 'rb') as infile:
        orig_size = int.from_bytes(infile.read(8), byteorder='big')
        vec = infile.read(16)
        decrypter = AES.new(key, AES.MODE_CBC, vec)

        with open(output_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decrypter.decrypt(chunk))

            outfile.truncate(orig_size)

def get_key(password):
    """Derive a 256-bit AES encryption key from the password"""
    salt = b'salt_'
    kdf = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return kdf

def LSB_AES_dec():
    # open the modified image file
    img = Image.open('hidden.png')

    # convert the image to RGB format
    img = img.convert('RGB')

    # extract the LSBs of the pixels
    binary_message = ''
    for y in range(img.height):
        for x in range(img.width):
            pixel = list(img.getpixel((x, y)))
            for j in range(3):
                binary_message += str(pixel[j] & 1)


    # extract the length of the message from the header
    binary_length = binary_message[:32]
    message_length = int(binary_length, 2)

    #key extract
    sec_key = binary_message[32:64]

    #key entry
    print("|=================================================================|")
    enter_key = input(" Enter the Security key   🗝️  :")
    print("|=================================================================|\n| Checking for Security Key ...                                   |\n|                                                                 |")

    #key convert to binary 32 bit form
    se_key = bytes(enter_key, 'utf-8')
    bin_sec_key = ''.join(format(byte, '08b') for byte in se_key)
    key_l = '{0:032s}'.format(bin_sec_key)

    if sec_key == key_l:
        print("| ✅ Matched                                                      |\n|=================================================================|")
        # extract the binary message
        binary_message = binary_message[64:64+message_length*8]

        # convert the binary message to its original format
        message = bytearray(int(binary_message[i:i+8], 2)
                            for i in range(0, len(binary_message), 8))
        
        # save the extracted message to a file
        with open('LSB_extracted_message.txt', 'wb') as f:
            f.write(message)

        # AES Decryption here
        password = input(" Enter key for decryption 🔐 : ")
        key = get_key(password)
        print("|=================================================================|")
        print("| If entered key is correct the decrytption will result in orignal|")
        print("| message !                                                       |")
        print("| See the result in Final_message.txt file !                      |")
        print("|=================================================================|")

        input_file = "LSB_extracted_message.txt"
        output_file = "Final_message.txt"
        decrypt_file(key, input_file, output_file)

    else:
        print("| ❌ Wrong Security key entered!                                  |")
        print("|=================================================================|")

if __name__=="__main__":
    LSB_AES_dec()