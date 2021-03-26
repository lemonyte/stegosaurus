from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def GenerateKeyPair(dir = "", size = 3072):
    keyPair = RSA.generate(size)
    privateKey = keyPair.export_key()
    with open(dir + "private.pem", "wb") as outputFile:
        outputFile.write(privateKey)

    publicKey = keyPair.publickey().export_key()
    with open(dir + "public.pem", "wb") as outputFile:
        outputFile.write(publicKey)

def ImportKey(keyPath):
    key = RSA.import_key(open(keyPath, "rb").read())
    return key

def Encrypt(message, publicKey):
    encryptor = PKCS1_OAEP.new(publicKey)
    encrypted = encryptor.encrypt(bytes(message, "utf-8"))
    return encrypted

def Decrypt(encrypted, privateKey):
    decryptor = PKCS1_OAEP.new(privateKey)
    decrypted = decryptor.decrypt(encrypted)
    return decrypted