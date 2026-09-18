import importlib.util
import os
import socket
import sys


def load_module(filename: str, module_name: str):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

HOST = "127.0.0.1"
PORT = 65432
KEY_BITS = 128  
OUTPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else ""


def resolve_output_path(kind: str, name: str) -> str:
    if OUTPUT_FILE:
        return OUTPUT_FILE
    if kind == "file":
        return f"received_{name}"
    return "received_text.txt"


def main():
    utils = load_module("2105085_utils.py", "utils")
    dh = load_module("2105085_dh.py", "dh")
    aes = load_module("2105085_aes.py", "aes")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        print(f"[Bob] Listening on {HOST}:{PORT} ...")
        conn, addr = server_sock.accept()

        with conn:
            print(f"[Bob] Connected by {addr}")

        
            P = utils.recv_int(conn)
            g = utils.recv_int(conn)
            A = utils.recv_int(conn)
            print(f"[Bob] Received P={P}, g={g}, A={A}")

           
            Kb, B = dh.generate_private_public(P, g, KEY_BITS)
            conn.sendall(utils.int_to_bytes(B))

            
            shared = dh.compute_shared_secret(A, Kb, P)
            aes_key = dh.derive_aes_key(shared, KEY_BITS)
            print("[Bob] Shared secret established.")

           
            conn.sendall(b"READY")

            
            header = utils.recv_bytes_with_length(conn)
            kind, name = header.decode("utf-8").split("|", 1)
            ciphertext = utils.recv_bytes_with_length(conn)
            plaintext = aes.cbc_decrypt(ciphertext, aes_key)
            output_path = resolve_output_path(kind, name)

            with open(output_path, "wb") as f:
                f.write(plaintext)

            if kind == "text":
                print(f"[Bob] Decrypted text: {plaintext.decode('utf-8', errors='replace')}")
            print(f"[Bob] Decrypted {kind} written to {output_path} ({len(plaintext)} bytes)")


if __name__ == "__main__":
    main()