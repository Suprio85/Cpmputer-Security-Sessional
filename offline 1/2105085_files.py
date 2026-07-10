import importlib.util
import os


def load_module(filename: str, module_name: str):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encrypt_file(key,path,mode:str="cbc") :
    aes = load_module("2105085_aes.py", "aes")
    with open(path,"rb") as f:
        data = f.read()

    ciphertext =""
    if mode == "cbc" :
        ciphertext = aes.cbc_encrypt(data,key)
    else :
        ciphertext = aes.ecb_encrypt(data,key)
    out_path = "cypher.enc"
    
    with open(out_path, "wb") as f :
        f.write(ciphertext)
    
    return out_path


def decrypt_file (key,in_path:str = "cypher.enc", out_path:str = "decypher.txt" , mode:str ="cbc") :

    aes = load_module("2105085_aes.py","aes")

    with open(in_path, "rb") as f :
        data = f.read()
    plain_text = ""
    if mode == "cbc" :
        plain_text = aes.cbc_decrypt(data,key)
    else :
        plain_text = aes.ecb_decrypt(data,key)

    with open(out_path,"wb") as f :
        f.write(plain_text)
    
if __name__ == "__main__" :
    key = b"BUET CSE20 Batch"

    encrypt_file(key, "aes_helpers.py")

    decrypt_file(key)

