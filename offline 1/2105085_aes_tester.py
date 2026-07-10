import importlib.util
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AES_FILE = os.path.join(BASE_DIR, "2105085_aes.py")


def load_module(filename: str, module_name: str):
    path = os.path.join(BASE_DIR, filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_demo(mode: str, key_text: str, plaintext: str, key_bits: int):
    aes = load_module("2105085_aes.py", "aes")

    key = aes.normalize_key(key_text.encode("utf-8"), size_bytes=key_bits // 8)
    data = plaintext.encode("utf-8")

    if mode == "ecb":
        ciphertext = aes.ecb_encrypt(data, key)
        recovered = aes.ecb_decrypt(ciphertext, key)
    else:
        ciphertext = aes.cbc_encrypt(data, key)
        recovered = aes.cbc_decrypt(ciphertext, key)

    print(f"AES-{key_bits} / {mode.upper()}")
    print(f"Key (ASCII): {key_text}")
    print(f"Key (HEX):   {aes.hex_str(key)}")
    print(f"Plaintext (ASCII): {plaintext}")
    print(f"Plaintext (HEX):   {aes.hex_str(data)}")
    print(f"Ciphertext (HEX):  {aes.hex_str(ciphertext)}")
    print(f"Ciphertext (ASCII): {ciphertext.decode('latin-1')}")
    print(f"Recovered (ASCII): {recovered.decode('utf-8', errors='replace')}")
    print(f"Recovered (HEX):   {aes.hex_str(recovered)}")
    print(f"Match: {recovered == data}")


def prompt_text(prompt: str, default: str) -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def prompt_int(prompt: str, default: int, valid_values) -> int:
    while True:
        value = input(f"{prompt} [{default}]: ").strip()
        if not value:
            return default
        try:
            number = int(value)
        except ValueError:
            print("Please enter a valid number.")
            continue
        if valid_values and number not in valid_values:
            print(f"Please choose one of: {', '.join(str(item) for item in valid_values)}")
            continue
        return number


def main():
    print("AES Demo Runner")
    mode = prompt_text("Enter mode (ecb/cbc)", "cbc").lower()
    while mode not in {"ecb", "cbc"}:
        print("Please enter either ecb or cbc.")
        mode = prompt_text("Enter mode (ecb/cbc)", "cbc").lower()

    key_bits = prompt_int("Enter key size in bits", 128, {128, 192, 256})
    key_text = prompt_text("Enter key text", "BUET CSE21 Batch")
    plaintext = prompt_text("Enter plaintext", "We need picnic")

    run_demo(mode, key_text, plaintext, key_bits)


if __name__ == "__main__":
    main()

