import importlib.util
import os
import socket
import sys

HOST = "127.0.0.1"
PORT = 65432
KEY_BITS = 128  
DEFAULT_TEXT = "We need picnic"

def load_module(filename: str, module_name: str):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve_payload():
    args = sys.argv[1:]
    if not args:
        return "text", "message.txt", DEFAULT_TEXT.encode("utf-8")

    source = " ".join(args)
    if source.startswith("text:"):
        text = source[len("text:") :]
        return "text", "message.txt", text.encode("utf-8")

    if source.startswith("file:"):
        path = source[len("file:") :]
    elif len(args) == 1 and os.path.isfile(args[0]):
        path = args[0]
    else:
        return "text", "message.txt", source.encode("utf-8")

    with open(path, "rb") as f:
        payload = f.read()
    return "file", os.path.basename(path), payload


def main():
    utils = load_module("2105085_utils.py", "utils")
    dh = load_module("2105085_dh.py", "dh")
    aes = load_module("2105085_aes.py", "aes")

   
    P, g = dh.generate_public_params(KEY_BITS)
    Ka, A = dh.generate_private_public(P, g, KEY_BITS)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[Alice] Connected to Bob at {HOST}:{PORT}")

        sock.sendall(utils.int_to_bytes(P))
        sock.sendall(utils.int_to_bytes(g))
        sock.sendall(utils.int_to_bytes(A))
  

        B = utils.recv_int(sock)
        print(f"[Alice] Received B={B}")

       
        shared = dh.compute_shared_secret(B, Ka, P)
        aes_key = dh.derive_aes_key(shared, KEY_BITS)
        print("[Alice] Shared secret established.")

      
        ready = sock.recv(5)
        print(f"[Alice] Bob says: {ready}")

        kind, name, payload = resolve_payload()
        header = f"{kind}|{name}".encode("utf-8")

        ciphertext = aes.cbc_encrypt(payload, aes_key)
        utils.send_bytes_with_length(sock, header)
        utils.send_bytes_with_length(sock, ciphertext)
        if kind == "file":
            print(f"[Alice] Sent file '{name}' as ciphertext ({len(ciphertext)} bytes)")
        else:
            print(f"[Alice] Sent text message as ciphertext ({len(ciphertext)} bytes)")


if __name__ == "__main__":
    main()