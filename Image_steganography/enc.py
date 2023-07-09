from PIL import Image
import os
import hashlib
from Crypto.Cipher import AES


def encrypt_file(key, input_filename, output_filename=None, chunksize=64*1024):
    #Encrypts a file using AES (CBC mode) with the given key.
    if not output_filename:
        output_filename = input_filename + '.txt'

    vec = os.urandom(16)
    encrypter = AES.new(key, AES.MODE_CBC, vec)
    size_of_file = os.path.getsize(input_filename)

    with open(input_filename, 'rb') as infile:
        with open(output_filename, 'wb') as outfile:
            outfile.write(size_of_file.to_bytes(8, byteorder='big'))
            outfile.write(vec)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encrypter.encrypt(chunk))


def get_key(password):
    #Derive a 256-bit AES encryption key from the password
    salt = b'salt_'
    AES_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return AES_key


def AES_enc():
    # AES Encryption here
    password = input("|=================================================================|\n Enter key for AES encryption 🔐 : ")
    key = get_key(password)

    input_file = "message.txt"
    output_file = "AES_encrypted_message.txt"
    encrypt_file(key, input_file, output_file)

def LSB_enc():
    # open the image file
    img = Image.open('image.png')

    # convert the image to RGB format
    img = img.convert('RGB')

    # open the message file and read it in binary format
    with open('AES_encrypted_message.txt', 'rb') as f:
        message = f.read()

    # convert message lenght in binary format
    message_length = len(message)
    binary_length = '{0:032b}'.format(message_length)

    #enter a secreat key for LSB
    security_key = input(" Enter the Security key       🗝️  :")
    print("|=================================================================|")
    #convert secreat key to binary forem
    sec_key = bytes(security_key, 'utf-8')
    bin_sec_key = ''.join(format(byte, '08b') for byte in sec_key)
    #32 bit secreat key
    key_l = '{0:032s}'.format(bin_sec_key)

    # convert the message to binary format
    binary_message = ''.join(format(byte, '08b') for byte in message)

    # concatenate the length of message and secreat key to the header of the message
    full_message = binary_length + key_l + binary_message

    print("| Checking for Image size...                                      |\n|                                                                 |")
    # check if the message will fit in the image
    if len(full_message) > img.width * img.height * 3:
        print("| ❌ Image size is small to hide message, Try with bigger image   |\n|=================================================================|\n")
        exit()
    print("| ✅ Checked                                                      |\n|=================================================================|")
    print("| ⬇️  Saving Hidded Image...                                       |\n|                                                                 |")
    # loop through the pixels in the image and modify the LSBs
    i = 0
    for y in range(img.height):
        for x in range(img.width):
            pixel = list(img.getpixel((x, y)))
            for j in range(3):
                if i < len(full_message):
                    pixel[j] = pixel[j] & ~1 | int(full_message[i])
                    i += 1
            img.putpixel((x, y), tuple(pixel))

    # save the modified image
    img.save('hidden.png')
    print("| ✅ Saved                                                        |\n|=================================================================|")

if __name__=="__main__":
    AES_enc()
    LSB_enc()