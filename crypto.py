from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def GenerateKeyPair(dir = '', size = 3072):
    keyPair = RSA.generate(size)
    privateKey = keyPair.export_key()
    with open(dir + '/' + str(size) + '_private.pem', 'wb') as outputFile:
        outputFile.write(privateKey)

    publicKey = keyPair.publickey().export_key()
    with open(dir + '/' + str(size) + '_public.pem', 'wb') as outputFile:
        outputFile.write(publicKey)

def ImportKey(keyPath):
    key = RSA.import_key(open(keyPath, 'rb').read())
    return key

def EncryptRSA(data, publicKey):
    encryptor = PKCS1_OAEP.new(publicKey)
    if type(data) == str:
        encrypted = encryptor.encrypt(bytes(data, 'utf-8'))

    elif type(data) == bytes:
        encrypted = encryptor.encrypt(data)

    return encrypted

def DecryptRSA(encrypted, privateKey):
    decryptor = PKCS1_OAEP.new(privateKey)
    decrypted = decryptor.decrypt(encrypted)
    return decrypted

def EncryptAES(data, publicKeyPath, outputFilePath = None, header = None, size = 16):
    publicKey = RSA.import_key(open(publicKeyPath).read())
    sessionKey = get_random_bytes(size)
    sessionKeyEncrypted = EncryptRSA(sessionKey, publicKey)
    encryptor = AES.new(sessionKey, AES.MODE_GCM)
    if type(header) == str:
        headerLength = str(len(header))
        if len(headerLength) == 1:
            headerLength = '0' + headerLength

        header = bytes(headerLength + header, 'utf-8')

    elif header is None:
        header = bytes('00', 'utf-8')

    encryptor.update(header)
    if type(data) == str:
        ciphertext, tag = encryptor.encrypt_and_digest(bytes(data, 'utf-8'))
    
    elif type(data) == bytes:
        ciphertext, tag = encryptor.encrypt_and_digest(data)
        
    if outputFilePath is not None:
        outputFile = open(outputFilePath, 'wb')
        [outputFile.write(x) for x in (header, sessionKeyEncrypted, encryptor.nonce, tag, ciphertext)]
        outputFile.close()

    return header, sessionKeyEncrypted, encryptor.nonce, tag, ciphertext

def DecryptAES(inputFilePath, privateKeyPath, outputFilePath = None):
    privateKey = RSA.import_key(open(privateKeyPath).read())
    inputFile = open(inputFilePath, 'rb')
    headerLength = int(inputFile.read(2))
    inputFile.seek(0)
    header, sessionKeyEncrypted, nonce, tag, ciphertext = [inputFile.read(x) for x in (2 + headerLength, privateKey.size_in_bytes(), 16, 16, -1)]
    sessionKey = DecryptRSA(sessionKeyEncrypted, privateKey)
    decryptor = AES.new(sessionKey, AES.MODE_GCM, nonce)
    decryptor.update(header)
    decrypted = decryptor.decrypt_and_verify(ciphertext, tag)
    if outputFilePath is not None:
        with open(outputFilePath, 'wb') as outputFile:
            outputFile.write(decrypted)

    inputFile.close()
    return decrypted, str(header, 'utf-8')