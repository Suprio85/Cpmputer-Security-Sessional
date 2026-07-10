import importlib.util
import os

from PIL import Image


def load_module(filename: str, module_name: str):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    aes = load_module("2105085_aes.py", "aes")

    key = b"BUET CSE20 Batch" 

  
    img = Image.open("buet1.png").convert("RGB")
    img = img.resize((64, 64))
    width, height = img.size
    raw_pixels = img.tobytes()

   
    ecb_cipher = aes.ecb_encrypt(raw_pixels, key)
    cbc_cipher = aes.cbc_encrypt(raw_pixels, key)
    pixel_len = width * height * 3

    ecb_img = Image.frombytes("RGB", (width, height), ecb_cipher[:pixel_len])
    cbc_img = Image.frombytes("RGB", (width, height), cbc_cipher[16:16 + pixel_len])

    ecb_img.save("output_ecb.png")
    cbc_img.save("output_cbc.png")
    


if __name__ == "__main__":
    main()