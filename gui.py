import os, rsa, stego
import PySimpleGUI as sg

sg.theme("Black")

def UpdateElement(elementKey: str, message: str = "", textColor: str = "white", visible: bool = True, textElement: bool = True):
    if textElement == True:
        window.Element(elementKey).update(message, text_color=textColor, visible=visible)

    elif textElement == False:
        window.Element(elementKey).update(visible=visible)

tab1_layout = [
    [sg.Checkbox("Encrypt with RSA encryption", key="rsa_checkbox", default=True, change_submits=True)], 
    [sg.Checkbox("Hide message inside image", key="image_checkbox", default=True, change_submits=True)], 

    [sg.Text(text="Output folder", key="output_dir_title")], 
    [sg.Column([[sg.In(key="output_dir"), sg.FolderBrowse(key="output_dir_browse")]], key="output_dir_row")], 
    [sg.Text(text="", key="output_dir_message", size=(40, 2))], 

    [sg.Text(text="Public key", key="public_key_title")], 
    [sg.Column([[sg.In(key="public_key"), sg.FileBrowse(key="public_key_browse", file_types=(("PEM Files", "*.pem"), ))]], key="public_key_row")], 
    [sg.Text(text="", key="public_key_message", size=(40, 2))], 

    [sg.Text(text="Image file", key="image_file_title")], 
    [sg.Column([[sg.In(key="image_file"), sg.FileBrowse(key="image_file_browse", file_types=(("PNG Files", "*.png"), ))]], key="image_file_row")], 
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
    [sg.Column([[sg.In(key="private_key"), sg.FileBrowse(key="private_key_browse", file_types=(("PEM Files", "*.pem"), ))]], key="private_key_row")], 
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

layout = [
    [sg.TabGroup(
        [
            [sg.Tab("Encrypt", tab1_layout), sg.Tab("Decrypt", tab2_layout), sg.Tab("Keys", tab3_layout)]
        ]
    )]
]

window = sg.Window("Stegosaurus", layout)
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break

    elif event == "generate_button":
        if not os.path.exists(values["keys_dir"]):
            UpdateElement("keys_dir_message", "Invalid folder", "red")
        
        else:
            rsa.GenerateKeyPair(values["keys_dir"])
            UpdateElement("keys_dir_message", "Sucessfully generated key pair", "green")

    elif event == "encrypt_button":
        if values["rsa_checkbox"] and not values["image_checkbox"]:
            if not os.path.exists(values["output_dir"]):
                UpdateElement("output_dir_message", "Invalid folder", "red")

            if not os.path.exists(values["public_key"]):
                UpdateElement("public_key_message", "Invalid PEM file", "red")
            
            if os.path.exists(values["output_dir"]) and os.path.exists(values["public_key"]):
                UpdateElement("output_dir_message")
                UpdateElement("public_key_message")
                with open(values["output_dir"] + "\\encrypted", "wb") as outputFile:
                    try:
                        #publicKey = import_key(open(values["public_key"], "rb").read())
                        publicKey = rsa.ImportKey(values["public_key"])
                        outputFile.write(b"enc_" + rsa.Encrypt(values["message"], publicKey))
                        UpdateElement("encrypt_message", "Successfully encrypted", "green")
                        
                    except:
                        UpdateElement("encrypt_message", "Unable to encrypt", "red")

        elif values["image_checkbox"] and not values["rsa_checkbox"]:
            if not os.path.exists(values["output_dir"]):
                UpdateElement("output_dir_message", "Invalid folder", "red")

            if not os.path.exists(values["image_file"]):
                UpdateElement("image_file_message", "Invalid PNG file", "red")

            if os.path.exists(values["output_dir"]) and os.path.exists(values["image_file"]):
                UpdateElement("output_dir_message")
                UpdateElement("image_file_message")
                try:
                    stego.Encode(values["image_file"], "pln_" + values["message"], values["output_dir"] + "\\encrypted.png")
                    UpdateElement("encrypt_message", "Successfully encrypted", "green")

                except:
                    UpdateElement("encrypt_message", "Unable to encrypt", "red")

        elif values["image_checkbox"] and  values["rsa_checkbox"]:
            if not os.path.exists(values["output_dir"]):
                UpdateElement("output_dir_message", "Invalid folder", "red")

            if not os.path.exists(values["public_key"]):
                UpdateElement("public_key_message", "Invalid PEM file", "red")

            if not os.path.exists(values["image_file"]):
                UpdateElement("image_file_message", "Invalid PNG file", "red")

            if os.path.exists(values["output_dir"]) and os.path.exists(values["public_key"]) and os.path.exists(values["image_file"]):
                UpdateElement("output_dir_message")
                UpdateElement("public_key_message")
                UpdateElement("image_file_message")
                try:
                    publicKey = rsa.ImportKey(values["public_key"])
                    encrypted = "enc_" + str(bytes.hex(rsa.Encrypt(values["message"], publicKey)))
                    stego.Encode(values["image_file"], encrypted, values["output_dir"] + "\\encrypted.png")
                    UpdateElement("encrypt_message", "Successfully encrypted", "green")

                except:
                    UpdateElement("encrypt_message", "Unable to encrypt", "red")

    elif event == "decrypt_button":
        if not os.path.exists(values["encrypted_file"]):
            UpdateElement("encrypted_file_message", "Invalid file", "red")

        if str(values["encrypted_file"]).split(".")[-1].lower() == "png":
            if os.path.exists(values["encrypted_file"]):
                UpdateElement("encrypted_file_message")
                UpdateElement("private_key_message")
                try:
                    decrypted = stego.Decode(values["encrypted_file"])
                    if str(decrypted[0:4]) == "enc_":
                        if not os.path.exists(values["private_key"]):
                            UpdateElement("private_key_message", "Invalid PEM file", "red")

                        if os.path.exists(values["private_key"]):
                            privateKey = rsa.ImportKey(values["private_key"])
                            UpdateElement("decrypted_message", str(rsa.Decrypt(bytes.fromhex(decrypted[4:]), privateKey), "utf-8"))
                            UpdateElement("decrypt_message", "Successfully decrypted file", "green")

                    elif str(decrypted[0:4]) == "pln_":
                        UpdateElement("decrypted_message", decrypted[4:])
                        UpdateElement("decrypt_message", "Successfully decrypted file", "green")

                except:
                    UpdateElement("decrypted_message")
                    UpdateElement("decrypt_message", "Unable to decrypt file", "red")

        if str(values["encrypted_file"]).split(".")[-1].lower() != "png":
            if not os.path.exists(values["private_key"]):
                UpdateElement("private_key_message", "Invalid PEM file", "red")

            if os.path.exists(values["encrypted_file"]) and os.path.exists(values["private_key"]):
                UpdateElement("encrypted_file_message")
                UpdateElement("private_key_message")
                try:
                    privateKey = rsa.ImportKey(values["private_key"])
                    file = open(values["encrypted_file"], "rb").read()
                    UpdateElement("decrypted_message", str(rsa.Decrypt(file[4:], privateKey), "utf-8"))
                    UpdateElement("decrypt_message", "Successfully decrypted file", "green")

                except:
                    UpdateElement("decrypted_message")
                    UpdateElement("decrypt_message", "Unable to decrypt file", "red")
        
    if values["image_checkbox"] == False:
        UpdateElement("image_file_title", visible=False, textElement=False)
        UpdateElement("image_file_row", visible=False, textElement=False)
        UpdateElement("image_file_message", visible=False, textElement=False)

    elif values["image_checkbox"] == True:
        UpdateElement("image_file_title", visible=True, textElement=False)
        UpdateElement("image_file_row", visible=True, textElement=False)
        UpdateElement("image_file_message", visible=True, textElement=False)

    if values["rsa_checkbox"] == False:
        UpdateElement("public_key_title", visible=False, textElement=False)
        UpdateElement("public_key_row", visible=False, textElement=False)
        UpdateElement("public_key_message", visible=False, textElement=False)

    elif values["rsa_checkbox"] == True:
        UpdateElement("public_key_title", visible=True, textElement=False)
        UpdateElement("public_key_row", visible=True, textElement=False)
        UpdateElement("public_key_message", visible=True, textElement=False)

window.close()