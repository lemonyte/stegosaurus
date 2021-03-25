import os, rsa, stego
import PySimpleGUI as sg
from Crypto.PublicKey.RSA import import_key

sg.theme("Black")

tab1_layout = [
    [sg.Checkbox("Encrypt with RSA encryption", key="rsa_checkbox", default=True, change_submits=True)], 
    [sg.Checkbox("Hide message inside image", key="image_checkbox", default=True, change_submits=True)], 

    [sg.Text(text="Output folder", key="output_dir_title")], 
    [sg.Column([[sg.In(key="output_dir"), sg.FolderBrowse(key="output_dir_browse")]], key="output_dir_row")], 
    [sg.Text(text="", key="output_dir_message", size=(40, 2))], 

    [sg.Text(text="Public key", key="public_key_title")], 
    [sg.Column([[sg.In(key="public_key"), sg.FileBrowse(key="public_key_browse")]], key="public_key_row")], 
    [sg.Text(text="", key="public_key_message", size=(40, 2))], 

    [sg.Text(text="Image file", key="image_file_title")], 
    [sg.Column([[sg.In(key="image_file"), sg.FileBrowse(key="image_file_browse")]], key="image_file_row")], 
    [sg.Text(text="", key="image_file_message", size=(40, 2))], 

    [sg.Text(text="Message", key="message_title")], 
    [sg.Multiline(default_text="Your message here.", size=(40, 10), key="message")], 
    [sg.Text(text="", key="encrypt_message", size=(40, 2))], 
    [sg.Button(key="encrypt_button", button_text="Encrypt")]
]

tab2_layout = [
    [sg.Text(text="Encrypted file", key="encrypted_file_title")], 
    [sg.Column([[sg.In(key="encrypted_file"), sg.FileBrowse(key="encrypted_file_browse")]], key="encrypted_file_row")], 
    [sg.Text(text="", key="encrypted_file_message", size=(40, 2))], 

    [sg.Text(text="Private key", key="private_key_title")], 
    [sg.Column([[sg.In(key="private_key"), sg.FileBrowse(key="private_key_browse")]], key="private_key_row")], 
    [sg.Text(text="", key="private_key_message", size=(40, 2))], 

    [sg.Text(text="Message", key="decrypted_message_title")], 
    [sg.Multiline(size=(40, 10), disabled=True, key="decrypted_message")], 
    [sg.Text(text="", key="decrypt_message", size=(40, 2))], 
    [sg.Button(key="decrypt_button", button_text="Decrypt")]
]

tab3_layout = [
    [sg.Text(text="Output folder")], 
    [sg.Column([[sg.In(key="keys_dir"), sg.FolderBrowse(key="keys_dir_browse")]], key="keys_dir_row")], 
    [sg.Text(text="", key="keys_dir_message", size=(40, 2))], 
    [sg.Button(key="generate_button", button_text="Generate Keys")]
]

layout = [[sg.TabGroup([[sg.Tab("Encrypt", tab1_layout), sg.Tab("Decrypt", tab2_layout), sg.Tab("Keys", tab3_layout)]])]]
window = sg.Window("Stegosaurus", layout)
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break

    elif event == "generate_button":
        if not os.path.exists(values["keys_dir"]):
            window.Element("keys_dir_message").update("Invalid folder", text_color="red")
        
        else:
            rsa.GenerateKeyPair(values["keys_dir"])
            window.Element("keys_dir_message").update("Sucessfully generated key pair", text_color="green")

    elif event == "encrypt_button":
        if values["rsa_checkbox"] == True:
            if not os.path.exists(values["output_dir"]):
                window.Element("output_dir_message").update("Invalid folder", text_color="red")

            if not os.path.exists(values["public_key"]):
                window.Element("public_key_message").update("Invalid PEM file", text_color="red")
            
            if os.path.exists(values["output_dir"]) and os.path.exists(values["public_key"]):
                window.Element("output_dir_message").update("")
                window.Element("public_key_message").update("")
                with open(values["output_dir"] + "\\encrypted.txt", "wb") as outputFile:
                    try:
                        publicKey = import_key(open(values["public_key"], "rb").read())
                        outputFile.write(rsa.Encrypt(values["message"], publicKey))
                        window.Element("encrypt_message").update("Successfully encrypted message", text_color="green")
                    except:
                        window.Element("encrypt_message").update("Unable to encrypt message", text_color="red")

    elif event == "decrypt_button":
        if not os.path.exists(values["encrypted_file"]):
            window.Element("encrypted_file_message").update("Invalid file", text_color="red")

        if not os.path.exists(values["private_key"]):
            window.Element("private_key_message").update("Invalid PEM file", text_color="red")

        if os.path.exists(values["encrypted_file"]) and os.path.exists(values["private_key"]):
            window.Element("encrypted_file_message").update("")
            window.Element("private_key_message").update("")
            try:
                privateKey = import_key(open(values["private_key"], "rb").read())
                window.Element("decrypted_message").update(str(bytes(rsa.Decrypt(open(values["encrypted_file"], "rb").read(), privateKey)), "utf-8"), "utf-8")
                window.Element("decrypt_message").update("Successfully decrypted message", text_color="green")
            except:
                window.Element("decrypt_message").update("Unable to decrypt file", text_color="red")

    
    if values["image_checkbox"] == False:
        window.Element("image_file_title").update(visible = False)
        window.Element("image_file_row").update(visible = False)
        window.Element("image_file_message").update(visible = False)

    elif values["image_checkbox"] == True:
        window.Element("image_file_title").update(visible = True)
        window.Element("image_file_row").update(visible = True)
        window.Element("image_file_message").update(visible = True)

    if values["rsa_checkbox"] == False:
        window.Element("public_key_title").update(visible = False)
        window.Element("public_key_row").update(visible = False)
        window.Element("public_key_message").update(visible = False)

    elif values["rsa_checkbox"] == True:
        window.Element("public_key_title").update(visible = True)
        window.Element("public_key_row").update(visible = True)
        window.Element("public_key_message").update(visible = True)

window.close()