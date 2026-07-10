import importlib.util
import os

MAX_LEN = 4


def load_module(filename: str, module_name: str):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def int_to_bytes(n: int) :
    length = max((n.bit_length() + 7) // 8,1) 
    return length.to_bytes(MAX_LEN) + n.to_bytes(length)


def recv_exact(sock, n: int) :
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed before expected data arrived")
        data += chunk
    return bytes(data)


def recv_int(sock) :
    length_bytes = recv_exact(sock, MAX_LEN)
    length = int.from_bytes(length_bytes)
    value_bytes = recv_exact(sock, length)
    return int.from_bytes(value_bytes)


def send_bytes_with_length(sock, data: bytes) :
    sock.sendall(len(data).to_bytes(MAX_LEN) + data)


def recv_bytes_with_length(sock) :
    length = int.from_bytes(recv_exact(sock, MAX_LEN))
    return recv_exact(sock, length)