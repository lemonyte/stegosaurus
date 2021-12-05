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
            [sg.Multiline(default_text='Your message here', size=(40, 15), key='message')],
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
            [sg.Combo(('2048', '3072', '4096', '8192'), default_value='3072', key='key_size')],
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


def save_file(path: str, data: bytes):
    try:
        with open(path, 'xb') as file:
            file.write(data)
    except FileExistsError:
        filename, extension = os.path.splitext(path)
        path = filename + '{}' + extension
        counter = 1
        while os.path.isfile(path.format(counter)):
            counter += 1
        path = path.format(counter)
        path = save_file(path, data)
    return path


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
                public_key, private_key = crypto.generate_key_pair(int(values['key_size']))
                save_file(f"{values['keys_dir']}/public_{values['key_size']}.pem", public_key)
                save_file(f"{values['keys_dir']}/private_{values['key_size']}.pem", private_key)
                window['keys_dir_message'].update("Successfully generated key pair", text_color='green')
            except Exception as exception:
                window['keys_dir_message'].update(f"Unable to generate key pair\n{exception}", text_color='red')

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
                            output_path = f"{values['output_dir']}/encrypted"
                            encrypted = crypto.encrypt_rsa(values['message'], values['public_key'], 'rsa_text')
                            save_file(output_path, encrypted)
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                        elif values['file_radio']:
                            with open(values['file'], 'rb') as input_file:
                                file_data = input_file.read()
                            output_path = f"{values['output_dir']}/{os.path.basename(values['file'])}.encrypted"
                            encrypted = crypto.encrypt_rsa(file_data, values['public_key'], f"rsa_file:{os.path.basename(values['file'])}")
                            save_file(output_path, encrypted)
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                elif values['image_checkbox']:
                    if os.path.exists(values['output_dir']) and os.path.exists(values['public_key']) and os.path.exists(values['image_file']):
                        window['output_dir_message'].update('')
                        window['public_key_message'].update('')
                        window['image_file_message'].update('')

                        if values['text_radio']:
                            encrypted = crypto.encrypt_rsa(values['message'], values['public_key'], 'rsa_text')
                            stego.encode(encrypted, values['image_file'], f"{values['output_dir']}/encrypted.png")
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                        elif values['file_radio']:
                            with open(values['file'], 'rb') as input_file:
                                file_data = input_file.read()
                            encrypted = crypto.encrypt_rsa(file_data, values['public_key'], f"rsa_file:{os.path.basename(values['file'])}")
                            stego.encode(encrypted, values['image_file'], f"{values['output_dir']}/encrypted.png")
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

            elif values['aes_radio']:
                if not values['image_checkbox']:
                    if os.path.exists(values['output_dir']) and os.path.exists(values['public_key']):
                        window['output_dir_message'].update('')
                        window['public_key_message'].update('')

                        if values['text_radio']:
                            output_path = f"{values['output_dir']}/encrypted"
                            encrypted = crypto.encrypt_aes(values['message'], values['public_key'], 'aes_text')
                            save_file(output_path, encrypted)
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                        elif values['file_radio']:
                            with open(values['file'], 'rb') as input_file:
                                file_data = input_file.read()
                            output_path = f"{values['output_dir']}/{os.path.basename(values['file'])}.encrypted"
                            encrypted = crypto.encrypt_aes(file_data, values['public_key'], f"aes_file:{os.path.basename(values['file'])}")
                            save_file(output_path, encrypted)
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                elif values['image_checkbox']:
                    if os.path.exists(values['output_dir']) and os.path.exists(values['public_key']) and os.path.exists(values['image_file']):
                        window['output_dir_message'].update('')
                        window['public_key_message'].update('')
                        window['image_file_message'].update('')

                        if values['text_radio']:
                            encrypted = crypto.encrypt_aes(values['message'], values['public_key'], 'aes_text')
                            stego.encode(encrypted, values['image_file'], f"{values['output_dir']}/encrypted.png")
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                        elif values['file_radio']:
                            with open(values['file'], 'rb') as input_file:
                                file_data = input_file.read()
                            encrypted = crypto.encrypt_aes(file_data, values['public_key'], f"aes_file:{os.path.basename(values['file'])}")
                            stego.encode(encrypted, values['image_file'], f"{values['output_dir']}/encrypted.png")
                            window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

            elif values['no_encryption_radio'] and values['image_checkbox']:
                if os.path.exists(values['output_dir']) and os.path.exists(values['image_file']):
                    window['output_dir_message'].update('')
                    window['image_file_message'].update('')

                    if values['text_radio']:
                        stego.encode('plain_text\u2028' + values['message'], values['image_file'], f"{values['output_dir']}/encrypted.png")
                        window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

                    elif values['file_radio']:
                        with open(values['file'], 'rb') as input_file:
                            file_data = input_file.read()
                        stego.encode(f"plain_file:{os.path.basename(values['file'])}\u2028".encode('utf-8') + file_data, values['image_file'], f"{values['output_dir']}/encrypted.png")
                        window['encrypt_message_text'].update("Successfully encrypted", text_color='green')

        except Exception as exception:
            window['encrypt_message_text'].update(f"Unable to encrypt\n{exception}", text_color='red')

    elif event == 'decrypt_button':
        if not os.path.exists(values['encrypted_file']):
            window['encrypted_file_message'].update("Invalid file", text_color='red')
        try:
            with open(values['encrypted_file'], 'rb') as input_file:
                encrypted = input_file.read()

            if values['encrypted_file'].split('.')[-1].lower() == 'png':
                encrypted = stego.decode(values['encrypted_file'])
                sep = '\u2028'.encode('utf-8')

                if encrypted.split(sep)[0] == b'plain_text':
                    window['decrypted_message'].update(encrypted.split(sep)[1].decode('utf-8'))
                    window['decrypt_message'].update('Successfully decrypted file', text_color='green')
                    continue

                elif encrypted.split(sep)[0].startswith(b'plain_file:'):
                    filename = encrypted.split(sep)[0].split(b':')[1].decode('utf-8')
                    decrypted = encrypted.split(sep)[1]
                    filename = save_file(f"{values['output_decrypt_dir']}/{filename}", decrypted)
                    try:
                        window['decrypted_message'].update(f"Saved decrypted data to file '{filename}'. Contents:\n\n{decrypted.decode('utf-8')}")
                    except Exception:
                        window['decrypted_message'].update(f"Saved decrypted data to file '{filename}'.")
                    window['decrypt_message'].update("Successfully decrypted file", text_color='green')
                    continue

            header = crypto.get_header(encrypted)

            if header == b'rsa_text':
                header, decrypted = crypto.decrypt_rsa(encrypted, values['private_key'])
                window['decrypted_message'].update(decrypted.decode('utf-8'))
                window['decrypt_message'].update("Successfully decrypted file", text_color='green')

            elif header == b'aes_text':
                header, decrypted = crypto.decrypt_aes(encrypted, values['private_key'])
                window['decrypted_message'].update(decrypted.decode('utf-8'))
                window['decrypt_message'].update("Successfully decrypted file", text_color='green')

            elif not os.path.exists(values['output_decrypt_dir']):
                window['output_decrypt_dir_message'].update("Invalid folder", text_color='red')

            elif header.startswith(b'rsa_file:'):
                filename = header.split(b':')[1].decode('utf-8')
                header, decrypted = crypto.decrypt_rsa(encrypted, values['private_key'])
                filename = save_file(f"{values['output_decrypt_dir']}/{filename}", decrypted)
                try:
                    window['decrypted_message'].update(f"Saved decrypted data to file '{filename}'. Contents:\n\n{decrypted.decode('utf-8')}")
                except Exception:
                    window['decrypted_message'].update(f"Saved decrypted data to file '{filename}'.")
                window['decrypt_message'].update("Successfully decrypted file", text_color='green')

            elif header.startswith(b'aes_file:'):
                filename = header.split(b':')[1].decode('utf-8')
                header, decrypted = crypto.decrypt_aes(encrypted, values['private_key'])
                filename = save_file(f"{values['output_decrypt_dir']}/{filename}", decrypted)
                try:
                    window['decrypted_message'].update(f"Saved decrypted data to file '{filename}'. Contents:\n\n{decrypted.decode('utf-8')}")
                except Exception:
                    window['decrypted_message'].update(f"Saved decrypted data to file '{filename}'.")
                window['decrypt_message'].update("Successfully decrypted file", text_color='green')

            else:
                window['decrypted_message'].update('')
                window['decrypt_message'].update("Unable to decrypt file\nUnknown file", text_color='red')

        except Exception as exception:
            window['decrypted_message'].update('')
            window['decrypt_message'].update(f"Unable to decrypt file\n{exception}", text_color='red')

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
