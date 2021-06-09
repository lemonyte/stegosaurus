import os
import PySimpleGUI as sg
import crypto
import stego

sg.theme('Black')

tab1_layout = [
    [
        sg.Column([
            [sg.Radio("Encrypt with AES encryption", group_id='aes_rsa_radios', key='aes_radio', default=True, enable_events=True)],
            [sg.Radio("Encrypt with RSA encryption", group_id='aes_rsa_radios', key='rsa_radio', default=False, enable_events=True)],
            [sg.Radio("Do not encrypt", group_id='aes_rsa_radios', key='no_encryption_radio', default=False, enable_events=True)],
            [sg.Checkbox("Hide data inside image", key='image_checkbox', default=True, enable_events=True)],

            [sg.Text(text="Output folder", key='output_dir_title')],
            [sg.Column([[sg.Input(key='output_dir'), sg.FolderBrowse(key='output_dir_browse')]], key='output_dir_row')],
            [sg.Text(text='', key='output_dir_message', size=(40, 2))],

            [sg.Text(text="Public key", key='public_key_title')],
            [sg.Column([[sg.Input(key='public_key', disabled_readonly_background_color='black'), sg.FileBrowse(key='public_key_browse', file_types=(('PEM Files', '*.pem'), ))]], key='public_key_row')],
            [sg.Text(text='', key='public_key_message', size=(40, 2))],

            [sg.Text(text="Image file", key='image_file_title')],
            [sg.Column([[sg.Input(key='image_file', disabled_readonly_background_color='black'), sg.FileBrowse(key='image_file_browse', file_types=(('PNG Files', '*.png'), ))]], key='image_file_row')],
            [sg.Text(text='', key='image_file_message', size=(40, 2))]
        ], vertical_alignment='top'),
        sg.VerticalSeparator(),
        sg.Column([
            [
                sg.Radio("Text", 'text_file_radios', key='text_radio', default=True, enable_events=True),
                sg.Radio("File", 'text_file_radios', key='file_radio', default=False, enable_events=True)
            ],

            [sg.Text(text="File", key='file_title')],
            [sg.Column([[sg.Input(key='file', disabled_readonly_background_color='black', disabled=True), sg.FileBrowse(key='file_browse', disabled=True)]], key='file_row')],
            [sg.Text(text='', key='encrypt_file_text', size=(40, 2))],

            [sg.Text(text="Text", key='text_title')],
            [sg.Multiline(default_text='Your message here.', size=(40, 15), key='message')],
            [sg.Text(text='', key='encrypt_message_text', size=(40, 2))],

            [sg.Column([[sg.Button(button_text="Encrypt", key='encrypt_button')]])]
        ], vertical_alignment='top')
    ]
]

tab2_layout = [
    [
        sg.Column([
            [sg.Text(text="Encrypted file", key='encrypted_file_title')],
            [sg.Column([[sg.Input(key='encrypted_file'), sg.FileBrowse(key='encrypted_file_browse')]], key='encrypted_file_row')],
            [sg.Text(text='', key='encrypted_file_message', size=(40, 2))],

            [sg.Text(text="Private key", key='private_key_title')],
            [sg.Column([[sg.Input(key='private_key'), sg.FileBrowse(key='private_key_browse', file_types=(('PEM Files', '*.pem'), ))]], key='private_key_row')],
            [sg.Text(text='', key='private_key_message', size=(40, 2))],

            [sg.Text(text="Output folder", key='output_decrypt_dir_title')],
            [sg.Column([[sg.Input(key='output_decrypt_dir', disabled_readonly_background_color='black'), sg.FolderBrowse(key='output_decrypt_dir_browse')]], key='output_decrypt_dir_row')],
            [sg.Text(text='', key='output_decrypt_dir_message', size=(40, 2))]
        ], vertical_alignment='top'),
        sg.VerticalSeparator(),
        sg.Column([
            [sg.Text(text="Text", key='decrypted_message_title')],
            [sg.Multiline(size=(40, 15), disabled=True, key='decrypted_message')],
            [sg.Text(text='', key='decrypt_message', size=(40, 2))],
            [sg.Column([[sg.Button(button_text="Decrypt", key='decrypt_button')]])]
        ], vertical_alignment='top')
    ]
]

tab3_layout = [
    [
        sg.Column([
            [sg.Text("Key size")],
            [sg.Combo(('2048', '3072', '4096', '8192'), default_value='3072', key='key_size_combo')],
            [sg.Text("Output folder")],
            [sg.Column([[sg.Input(key='keys_dir'), sg.FolderBrowse(key='keys_dir_browse')]], key='keys_dir_row')],
            [sg.Text(text='', key='keys_dir_message', size=(40, 2))],
            [sg.Button(button_text="Generate keys", key='generate_button')]
        ], vertical_alignment='top')
    ]
]

layout = [
    [
        sg.TabGroup([
            [sg.Tab("Encrypt", tab1_layout), sg.Tab("Decrypt", tab2_layout), sg.Tab("Keys", tab3_layout)]
        ])
    ]
]

window = sg.Window("Stegosaurus", layout)
while True:
    window.refresh()
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break

    elif event == 'generate_button':
        if not os.path.exists(values['keys_dir']):
            window['keys_dir_message'].update("Invalid folder", text_color='red')

        else:
            try:
                crypto.GenerateKeyPair(values['keys_dir'], int(values['key_size_combo']))
                window['keys_dir_message'].update("Successfully generated key pair", text_color='green')

            except Exception as exception:
                window['keys_dir_message'].update("Unable to generate key pair\n" + str(exception), text_color='red')

    elif event == 'encrypt_button':
        if not os.path.exists(values['output_dir']):
            window['output_dir_message'].update("Invalid folder", text_color='red')

        if values['no_encryption_radio'] is False:
            if not os.path.exists(values['public_key']):
                window['public_key_message'].update("Invalid PEM file", text_color='red')

        if values['image_checkbox']:
            if not os.path.exists(values['image_file']):
                window['image_file_message'].update("Invalid PNG file", text_color='red')

        try:
            if values['rsa_radio']:
                if not values['image_checkbox']:
                    if os.path.exists(values['output_dir']) and os.path.exists(values['public_key']):
                        window['output_dir_message'].update('')
                        window['public_key_message'].update('')
                        if values['text_radio']:
                            with open(values['output_dir'] + '/encrypted', 'wb') as outputFile:
                                publicKey = crypto.ImportKey(values['public_key'])
                                outputFile.write(b'enct' + crypto.EncryptRSA(values['message'], publicKey))
                                window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                        elif values['file_radio']:
                            with open(values['output_dir'] + '/encrypted', 'wb') as outputFile:
                                fileExt = str(values['file']).split('.')[-1].lower()
                                if fileExt.find('/') != -1:
                                    fileExt = 'file'

                                fileExtLength = str(len(fileExt))
                                if len(fileExtLength) == 1:
                                    fileExtLength = '0' + fileExtLength

                                file = open(values['file'], 'rb').read()
                                publicKey = crypto.ImportKey(values['public_key'])
                                outputFile.write(b'encf' + bytes(fileExtLength, 'utf-8') + bytes(fileExt, 'utf-8') + crypto.EncryptRSA(str(file.hex()), publicKey))
                                window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                elif values['image_checkbox']:
                    if os.path.exists(values['output_dir']) and os.path.exists(values['public_key']) and os.path.exists(values['image_file']):
                        window['output_dir_message'].update('')
                        window['public_key_message'].update('')
                        window['image_file_message'].update('')
                        if values['text_radio']:
                            publicKey = crypto.ImportKey(values['public_key'])
                            encrypted = 'enct' + str(bytes.hex(crypto.EncryptRSA(values['message'], publicKey)))
                            stego.Encode(values['image_file'], encrypted, values['output_dir'] + '/encrypted.png')
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                        elif values['file_radio']:
                            fileExt = str(values['file']).split('.')[-1].lower()
                            if fileExt.find('/') != -1:
                                fileExt = 'file'

                            file = open(values['file'], 'rb').read()
                            publicKey = crypto.ImportKey(values['public_key'])
                            encrypted = 'encf' + str(len(fileExt)) + fileExt + str(bytes.hex(crypto.EncryptRSA(str(file.hex()), publicKey)))
                            stego.Encode(values['image_file'], encrypted, values['output_dir'] + '/encrypted.png')
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

            elif values['aes_radio']:
                if not values['image_checkbox']:
                    if os.path.exists(values['output_dir']) and os.path.exists(values['public_key']):
                        window['output_dir_message'].update('')
                        window['public_key_message'].update('')
                        if values['text_radio']:
                            with open(values['output_dir'] + '/encrypted', 'wb') as outputFile:
                                crypto.EncryptAES(values['message'], values['public_key'], values['output_dir'] + '/encrypted', 'enc_text_aes')
                                window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                        elif values['file_radio']:
                            with open(values['output_dir'] + '/encrypted', 'wb') as outputFile:
                                fileExt = str(values['file']).split('.')[-1].lower()
                                if fileExt.find('/') != -1:
                                    fileExt = 'file'

                                file = open(values['file'], 'rb').read()
                                crypto.EncryptAES(bytes.hex(file), values['public_key'], values['output_dir'] + '/encrypted', 'enc_file_aes_' + fileExt)
                                window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                elif values['image_checkbox']:
                    if os.path.exists(values['output_dir']) and os.path.exists(values['public_key']) and os.path.exists(values['image_file']):
                        window['output_dir_message'].update('')
                        window['public_key_message'].update('')
                        window['image_file_message'].update('')
                        if values['text_radio']:
                            header, sessionKeyEncrypted, nonce, tag, ciphertext = crypto.EncryptAES(values['message'], values['public_key'], header='enc_text_aes')
                            stego.Encode(values['image_file'], bytes.hex(header) + bytes.hex(sessionKeyEncrypted) + bytes.hex(nonce) + bytes.hex(tag) + bytes.hex(ciphertext), values['output_dir'] + '/encrypted.png')
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                        elif values['file_radio']:
                            fileExt = str(values['file']).split('.')[-1].lower()
                            if fileExt.find('/') != -1:
                                fileExt = 'file'

                            file = open(values['file'], 'rb').read()
                            header, sessionKeyEncrypted, nonce, tag, ciphertext = crypto.EncryptAES(bytes.hex(file), values['public_key'], header='enc_file_aes_' + fileExt)
                            stego.Encode(values['image_file'], bytes.hex(header) + bytes.hex(sessionKeyEncrypted) + bytes.hex(nonce) + bytes.hex(tag) + bytes.hex(ciphertext), values['output_dir'] + '/encrypted.png')
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

            elif values['no_encryption_radio'] and values['image_checkbox']:
                if os.path.exists(values['output_dir']) and os.path.exists(values['image_file']):
                    window['output_dir_message'].update('')
                    window['image_file_message'].update('')
                    if values['text_radio']:
                        stego.Encode(values['image_file'], 'plnt' + values['message'], values['output_dir'] + '/encrypted.png')
                        window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                    elif values['file_radio']:
                        fileExt = str(values['file']).split('.')[-1].lower()
                        if fileExt.find('/') != -1:
                            fileExt = 'file'

                        file = open(values['file'], 'rb').read()
                        stego.Encode(values['image_file'], 'plnf' + str(len(fileExt)) + fileExt + bytes.hex(file), values['output_dir'] + '/encrypted.png')
                        window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

        except Exception as exception:
            window['encrypt_message_text'].update("Unable to encrypt\n" + str(exception), text_color='red')

    elif event == 'decrypt_button':
        if not os.path.exists(values['encrypted_file']):
            window['encrypted_file_message'].update("Invalid file", text_color='red')

        try:
            if str(values['encrypted_file']).split('.')[-1].lower() != 'png':
                if not os.path.exists(values['private_key']):
                    window['private_key_message'].update("Invalid PEM file", text_color='red')

                else:
                    privateKey = crypto.ImportKey(values['private_key'])
                    file = open(values['encrypted_file'], 'rb').read()

                    if str(file[0:4], 'utf-8') == 'enct':
                        decrypted = str(crypto.DecryptRSA(file[4:], privateKey), 'utf-8')
                        window['decrypted_message'].update(decrypted)
                        window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                    elif str(file[0:4], 'utf-8') == '12en':
                        if str(file[0:14], 'utf-8') == '12enc_text_aes':
                            decrypted, header = crypto.DecryptAES(values['encrypted_file'], values['private_key'])
                            window['decrypted_message'].update(str(decrypted, 'utf-8'))
                            window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                    elif not os.path.exists(values['output_decrypt_dir']):
                        window['output_decrypt_dir_message'].update("Invalid folder", text_color='red')

                    elif str(file[0:4], 'utf-8') == 'encf':
                        fileExtLength = int(chr(file[4]) + chr(file[5]))
                        fileExt = str(file[6:(6 + fileExtLength)], 'utf-8')
                        decrypted = str(bytes.fromhex(str(crypto.DecryptRSA(file[(6 + fileExtLength):], privateKey), 'utf-8')), 'utf-8')
                        with open(values['output_decrypt_dir'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes(decrypted, 'utf-8'))

                        try:
                            window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + decrypted)

                        except Exception:
                            window['decrypted_message'].update("Saved decrypted data to file.")

                        window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                    elif str(file[0:14], 'utf-8').find('enc_file_aes') != -1:
                        decrypted, header = crypto.DecryptAES(values['encrypted_file'], values['private_key'])
                        fileExt = header[15:]
                        with open(values['output_decrypt_dir'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes.fromhex(str(decrypted, 'utf-8')))

                        try:
                            window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + str(bytes.fromhex(str(decrypted, 'utf-8')), 'utf-8'))

                        except Exception:
                            window['decrypted_message'].update("Saved decrypted data to file.")

                        window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                    else:
                        window['decrypted_message'].update('')
                        window['decrypt_message'].update("Unable to decrypt file\n" + "unknown file", text_color='red')

            elif str(values['encrypted_file']).split('.')[-1].lower() == 'png':
                if os.path.exists(values['encrypted_file']):
                    window['encrypted_file_message'].update('')
                    window['private_key_message'].update('')
                    file = stego.Decode(values['encrypted_file'])
                    try:
                        filefromhex = bytes.fromhex(file)

                    except Exception:
                        filefromhex = file

                    if file[0:4] == 'plnt':
                        window['decrypted_message'].update(file[4:])
                        window['decrypt_message'].update('Successfully decrypted file', text_color='green')

                    elif file[0:4] == 'plnf':
                        fileExtLength = int(file[4])
                        fileExt = file[5:(5 + fileExtLength)]
                        with open(values['output_decrypt_dir'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes.fromhex(file[(5 + fileExtLength):]))

                        try:
                            window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + str(bytes.fromhex(file[(5 + fileExtLength):]), 'utf-8'))

                        except Exception:
                            window['decrypted_message'].update("Saved decrypted data to file.")

                        window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                    elif not os.path.exists(values['private_key']):
                        window['private_key_message'].update("Invalid PEM file", text_color='red')

                    elif os.path.exists(values['private_key']):
                        privateKey = crypto.ImportKey(values['private_key'])
                        if file[0:4] == 'enct':
                            decrypted = str(crypto.DecryptRSA(bytes.fromhex(file[4:]), privateKey), 'utf-8')
                            window['decrypted_message'].update(decrypted)
                            window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                        elif not os.path.exists(values['output_decrypt_dir']):
                            window['output_decrypt_dir_message'].update("Invalid folder", text_color='red')

                        elif type(filefromhex) == bytes:
                            if str(filefromhex[0:14], 'utf-8') == '12enc_text_aes':
                                with open(values['output_decrypt_dir'] + '/aes_text_fromhex_temp', 'wb') as tempFile:
                                    tempFile.write(filefromhex)

                                decrypted, header = crypto.DecryptAES(values['output_decrypt_dir'] + '/aes_text_fromhex_temp', values['private_key'])
                                os.remove(values['output_decrypt_dir'] + '/aes_text_fromhex_temp')
                                window['decrypted_message'].update(str(decrypted, 'utf-8'))
                                window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                            elif str(filefromhex[0:14], 'utf-8').find('enc_file_aes') != -1:
                                with open(values['output_decrypt_dir'] + '/aes_file_fromhex_temp', 'wb') as tempFile:
                                    tempFile.write(filefromhex)

                                decrypted, header = crypto.DecryptAES(values['output_decrypt_dir'] + '/aes_file_fromhex_temp', values['private_key'])
                                fileExt = header[15:]
                                with open(values['output_decrypt_dir'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                                    outputFile.write(bytes.fromhex(str(decrypted, 'utf-8')))

                                try:
                                    window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + str(bytes.fromhex(str(decrypted, 'utf-8')), 'utf-8'))

                                except Exception:
                                    window['decrypted_message'].update("Saved decrypted data to file.")

                                os.remove(values['output_decrypt_dir'] + '/aes_file_fromhex_temp')
                                window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                        elif file[0:4] == 'encf':
                            fileExtLength = int(file[4] + file[5])
                            fileExt = file[6:(6 + fileExtLength)]
                            decrypted = str(bytes.fromhex(str(crypto.DecryptRSA(bytes.fromhex(file[(6 + fileExtLength):]), privateKey), 'utf-8')), 'utf-8')
                            with open(values['output_decrypt_dir'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                                outputFile.write(bytes(decrypted, 'utf-8'))

                            try:
                                window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + decrypted)

                            except Exception:
                                window['decrypted_message'].update("Saved decrypted data to file.")

                            window['decrypt_message'].update("Successfully decrypted file", text_color='green')

                    else:
                        window['decrypted_message'].update('')
                        window['decrypt_message'].update("Unable to decrypt file\n" + "unknown file", text_color='red')

        except Exception as exception:
            window['decrypted_message'].update('')
            window['decrypt_message'].update("Unable to decrypt file\n" + str(exception), text_color='red')

    if values['text_radio']:
        window['message'].update(disabled=False)
        window['message'].Widget.config(bg='#4D4D4D')
        window['file'].update(disabled=True)
        window['file_browse'].update(disabled=True)

    elif values['file_radio']:
        window['message'].update(disabled=True)
        window['message'].Widget.config(bg='#000000')
        window['file'].update(disabled=False)
        window['file_browse'].update(disabled=False)

    if values['no_encryption_radio']:
        window['image_checkbox'].update(True, disabled=True)
        window['image_file'].update(disabled=False)
        window['image_file_browse'].update(disabled=False)
        window['public_key'].update(disabled=True)
        window['public_key_browse'].update(disabled=True)

    elif not values['no_encryption_radio']:
        window['image_checkbox'].update(disabled=False)
        window['image_file'].update(disabled=False)
        window['image_file_browse'].update(disabled=False)
        window['public_key'].update(disabled=False)
        window['public_key_browse'].update(disabled=False)

    if values['image_checkbox']:
        window['image_file'].update(disabled=False)
        window['image_file_browse'].update(disabled=False)

    elif not values['image_checkbox'] and not values['no_encryption_radio']:
        window['image_file'].update(disabled=True)
        window['image_file_browse'].update(disabled=True)

window.close()
