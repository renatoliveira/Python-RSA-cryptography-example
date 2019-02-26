# Python RSA cryptography example

This script shows how one can use the `cryptography` library to write a script to generate an RSA key pair and use them to encrypt and decrypt data.

## Generating a key pair

	python keygen.py -s 2048 -o key

This command should generate an RSA key with the size of 2048 bits. It will output two files, called `key_pk` and `key_pub`. They are both the private and public keys.

## Encrypting a file

	python keygen.py -e file -k key_pub -o encryptedfile

This will encrypt the file `file` using the public key `key_pub` and will output the file `encryptedfile`.

## Decrypting a file

	python keygen.py -d file -k key_pk -o decryptedfile

This will decrypt the file `file` using the private key `key_pk` and will output the decrypted data into the file `decryptedfile`.

## Considerations

This is intended for learning purposes. The encryption won't work, for example, for data sets larger than 128kb, probably. If you try to encrypt a larger file than that, you'll get a ValueError exception thrown with the message _ValueError: Data too long for key size. Encrypt less data or use a larger key size._.

