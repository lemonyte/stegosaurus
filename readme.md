# Stegosaurus

A small app that can encrypt and decrypt text and files with AES and RSA encryption, as well as hide plain or encrypted data inside images.

## Requirements

### Python File

- [Python 3.9](https://www.python.org/downloads/) or higher
- Packages listed in [`requirements.txt`](requirements.txt)

### Windows Systems

Optional executable file for Windows users. Python and the required packages are included in the executable.

- 12 MB of free space for the executable
- 14 MB of free space for temporary files

## Usage

### Keys

You can generate an RSA key pair in the "Keys" tab. These keys are used for both the AES and RSA encryptions, with and without image encoding. The size of the key (in bits) is what determines how much data you are able to encrypt using that key. If you are using AES, the smallest size of 2048 bits is more than enough as the only data encrypted with this RSA key is the AES key itself. However, if you wish to encrypt more than a few bytes of data using purely RSA encryption, you will need to use a larger key, such as 3072 or 4096 bits. An 8192 bit option is included, but it is highly impractical, and it is better to simply use AES encryption instead.

### Encryption Options

There are 5 different combinations of encryption and encoding methods:  

- AES encryption
- RSA encryption
- Image encoding
- AES and image encoding
- RSA and image encoding

### AES Encryption

Can encrypt text and large files. An RSA key pair is still required for AES encryption because the AES key is encrypted with RSA encryption so it can be securely transmitted along with the encrypted data. This option is recommended over RSA encryption.

### RSA Encryption

Data is encrypted using only the RSA algorithm. Only useful for encrypting text or very small files (less than 1 KB). Cannot encrypt large files. AES encryption is recommended over this option.

### Image Encoding

Data is hidden inside the RGB values of a PNG image file. Every byte of data takes 3 pixels to hide, which means the total amount of bytes that can fit into an image is `l * w / 3`, where length and width are the dimensions or resolution of the image. For example:

```text
1920 * 1080 = 2,073,600 pixels
2,073,600 / 3 = 691,200 bytes can fit inside
691,200 / 1024 = 675 KB
```

This option does not encrypt data, it only encodes data into an image. Anyone with this app can decode the data. Using this option by itself without AES or RSA encryption is not recommended.

### AES and Image Encoding

Data is first encrypted with AES encryption, then the AES key is encrypted with RSA encryption, then the encrypted data and key are encoded into an image. This option is recommended over the other options with image encoding.

### RSA and Image Encoding

Data is encrypted with RSA encryption, then the encrypted data is encoded into an image. The same limitations outlined under [RSA Encryption](#rsa-encryption) apply here.

### Decryption

Decryption is done automatically, regardless of what encryptions were used and what kind of data was encrypted at the start. Specify the encrypted file or image, your private key (unless the data was encrypted using only image encoding), and an output directory if the original data was a file.

## Disclaimer

This software is not guaranteed to encrypt data safely or securely. Use of this software implies you have read this disclaimer and understand the risks. I am not liable for any data loss, damage, privacy damage, or other consequences resulting from use of this software.

## License

[MIT License](license.txt)
