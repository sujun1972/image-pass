import argparse
from stegano import lsb
from cryptography.fernet import Fernet
import base64
import hashlib

# Generate a key for encryption using the provided password
def generate_key(password):
    # Use hashlib to generate a 32-byte key from the password
    key = hashlib.sha256(password.encode()).digest()
    # Base64 encode the key to make it URL-safe
    key = base64.urlsafe_b64encode(key)
    return key

# Encrypt text using the provided key
def encrypt_text(text, key):
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode('utf-8'))
    return encrypted_text

# Decrypt text using the provided key
def decrypt_text(encrypted_text, key):
    cipher = Fernet(key)
    decrypted_text = cipher.decrypt(encrypted_text).decode('utf-8')
    return decrypted_text

# Hide text in an image
def hide_text_in_image(text, image_path, output_image_path):
    secret = lsb.hide(image_path, text)
    secret.save(output_image_path)

# Extract text from an image
def extract_text_from_image(image_path):
    clear_text = lsb.reveal(image_path)
    return clear_text

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt text and hide it in an image.')
    parser.add_argument('-c', '--encrypt', action='store_true', help='Encrypt text and hide it in an image')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Extract encrypted text from an image and decrypt')
    args = parser.parse_args()

    if args.encrypt and args.decrypt:
        print("Error: Please choose either -c or -d, not both.")
    elif args.encrypt:
        password = input("Enter a password for encryption and decryption: ")
        input_image_path = input("Enter the path to the input image: ")
        output_image_path = input("Enter the path for the output image: ")
        key = generate_key(password)
        input_text_file = input("Enter the path to the input text file: ")
        with open(input_text_file, 'r', encoding='utf-8') as file:
            text_to_hide = file.read()
        encrypted_text = encrypt_text(text_to_hide, key).decode('utf-8')
        secret = lsb.hide(input_image_path, encrypted_text)
        secret.save(output_image_path)
        print("Encrypted text hidden in image.")
    elif args.decrypt:
        password = input("Enter a password for encryption and decryption: ")
        key = generate_key(password)
        input_image_path = input("Enter the path to the image with hidden encrypted text: ")

        extracted_encrypted_text = lsb.reveal(input_image_path)
        decrypted_text = decrypt_text(extracted_encrypted_text.encode('utf-8'), key)
        output_text_file = input("Enter the path for the output text file: ")
        with open(output_text_file, 'w', encoding='utf-8') as file:
            file.write(decrypted_text)
        print("Decrypted text saved to:", output_text_file)

    else:
        print("Error: Please choose either -c to encrypt or -d to decrypt.")

if __name__ == "__main__":
    main()
