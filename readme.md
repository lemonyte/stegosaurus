# Stegosaurus
By [LemonPi314](https://github.com/LemonPi314)

A small app that can encrypt and decrypt text and files with AES and RSA encryption, as well as hide plain or encrypted data inside images.
## Requirements
### Python File
Any operating system with Python.
- [Python 3.9](https://www.python.org/downloads/) or higher
- [`PyCryptodome`](https://pypi.org/project/pycryptodome/)
- [`Pillow`](https://pypi.org/project/Pillow/)
- [`PySimpleGUI`](https://pypi.org/project/PySimpleGUI/)
### Windows Systems
Optional executable file for Windows users. Python and the required packages are included in the executable.
- 30 MB of free space for the executable
- 70 MB of free space for temporary files
## Usage
### Keys
You can generate an RSA key pair in the "Keys" tab. These keys are used for both the AES and RSA encryptions, with and without image encryption. The size of the key (in bits) is what determines how much data you are able to encrypt using that key. If you are using AES, the smallest size of 2048 bits is more than enough as the only data encrypted with this RSA key is the AES key itself. However, if you wish to encrypt more than a few bytes of data using purely RSA encryption, you will need to use a larger key, such as 3072 or 4096 bits. An 8192 bit option is included, but it is highly impractical, and it is better to simply use AES encryption instead.
### Encryption Options
There are 5 different combinations of encryption algorithms:  
- AES encryption
- RSA encryption
- Image encryption
- AES and image encryption
- RSA and image encryption
### AES Encryption
Can encrypt text and large files. The AES key is encrypted with RSA encryption so data can be securely transmitted using a public key system. This option is recommended over RSA encryption.
### RSA Encryption
Data is encrypted using only the RSA algorithm. Only useful for encrypting text or very small files (less than 1 KB). Cannot encrypt large files. AES encryption is recommended over this option.
### Image Encryption
Data is hidden inside the RGB values of a PNG image file. Every byte of data takes 3 pixels to hide, which means the total amount of bytes that can fit into an image is `l * w / 3`, where length and width are the dimensions or resolution of the image. For example: 
```
1920 * 1080 = 2,073,600 pixels
2,073,600 / 3 = 691,200 bytes can fit inside
691,200 / 1024 = 675 KB
```
Using this option by itself without AES or RSA encryption is not recommended, as anyone with access to this app can decrypt the data.
### AES and Image Encryption
Data is first encrypted with AES encryption, then the AES key is encrypted with RSA encryption, then the encrypted data and key are encoded into an image. This option is recommended over the other options with image encryption.
### RSA and Image Encryption
Data is encrypted with RSA encryption, then the encrypted data is encoded into an image. The same limitations outlined under [RSA Encryption](#rsa-encryption) apply here.
### Decryption
Decryption is done automatically, regardless of what encryptions were used and what kind of data was encrypted at the start. Specify the encrypted file or image, your private key (unless the data was encrypted using only image encryption), and an output directory if the data was a file before encryption. An output directory is also required for decrypting data encrypted with AES for temporary files.
## License
[MIT License](https://choosealicense.com/licenses/mit/)