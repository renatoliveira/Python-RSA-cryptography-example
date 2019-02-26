import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate(key_size: int):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def save_keys(pk, filename):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pbk = pk.public_key()
    pub = pbk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )
    with open(filename + '_pk', 'wb') as pem_out:
        pem_out.write(pem)
    with open(filename + '_pub', 'wb') as pub_out:
        pub_out.write(pub)


def encrypt_file(key_location: str, file_location: str, output_file: str):
    public_key = serialization.load_pem_public_key(
        open(key_location, 'rb').read(),
        backend=default_backend()
    )
    ciphertext = public_key.encrypt(
        open(file_location, 'rb').read(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_file, 'wb') as output:
        output.write(ciphertext)


def decrypt_file(key_location: str, file_location: str, output_file: str):
    private_key = serialization.load_pem_private_key(
        open(key_location, 'rb').read(),
        password=None,
        backend=default_backend()
    )
    data = private_key.decrypt(
        open(file_location, 'rb').read(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_file, 'wb') as output:
        output.write(data)


parser = argparse.ArgumentParser(description='Load and generate RSA keys')

# To generate a key
parser.add_argument(
    '-s',
    '--key-size',
    dest='key_size',
    help='Key size (2048 is recommended)'
)

# To encrypt or decrypt files
parser.add_argument(
    '-k',
    '--key',
    dest='key_location',
    help='Key to be used in the process of encryption or decryption.'
)
parser.add_argument(
    '-e',
    '--encrypt',
    dest='file_to_encrypt',
    help='File to encrypt'
)
parser.add_argument(
    '-d',
    '--decrypt',
    dest='file_to_decrypt',
    help='File to decrypt'
)

# Common arguments
parser.add_argument(
    '-o',
    '--file-name',
    dest='file_name',
    help='Output file name'
)

args = vars(parser.parse_args())


if 'key_size' in args and args['key_size'] is not None:
    save_keys(generate(int(args['key_size'])), args['file_name'])
elif 'key_location' in args:
    # decrypt or encrypt?
    if 'file_to_encrypt' in args and args['file_to_encrypt'] is not None:
        encrypt_file(
            args['key_location'],
            args['file_to_encrypt'],
            args['file_name']
        )
    elif 'file_to_decrypt' in args and args['file_to_decrypt'] is not None:
        decrypt_file(
            args['key_location'],
            args['file_to_decrypt'],
            args['file_name']
        )
