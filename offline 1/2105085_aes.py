import os
import time


from aes_helpers import Sbox, InvSbox , Rcon, Mixer , InvMixer , gf_mult


BLOCK_SIZE = 16
MAX_ROUNDS = 10
KEY_SCHEDULE = {
    16 : (4,10),
    24 : (6,12),
    32 : (8,14),
}

def byte_to_state(block:bytes) :
    
    state = [[0]*4 for _ in range(4)]
    sz = len(block)

    assert(sz == BLOCK_SIZE)

    for i in range(BLOCK_SIZE) :
        row = i % 4
        col = i // 4
        state[row][col] = block[i]
        
    # print(state)
    return state

def state_to_byte(state : list) :
    block = bytearray(BLOCK_SIZE)

    for i in range(BLOCK_SIZE) :
        row = i%4
        col = i//4
        block[i] = state[row][col]
    # // print(block)
    return bytes(block)

def sub_bytes(state) :
    
    for i in range(BLOCK_SIZE) :
        row = i%4
        col = i//4
        state[row][col] = Sbox[state[row][col]]

    return state

def inv_sub_bytes(state) :

    for i in range(BLOCK_SIZE) :
        row = i%4
        col = i//4
        state[row][col] = InvSbox[state[row][col]]

    return state

def shift_row(state) :
    for i in range(4) :
        # print(f"Before:{state[i]})
        state[i] = state[i][i:] + state[i][:i]
        # print(f"After :{state[i]})
    return state

def inv_shift_row(state) :
    for i in range(4) :
        state[i] = state[i][-i:]+state[i][:-i]
    return state


def mix_single_column(col:list, mat) :
    result =  [0]*4

    for i in range(4) :
        val = 0
        for j in range(4) :
            val ^= gf_mult(mat[i][j], col[j])
        result[i] = val
    
    return result
        

def mix_columns(state) :

    for col in range(4) :
        column = [state[row][col] for row in range(4)]
        res = mix_single_column(column,Mixer)

        for row in range(4) :
            state[row][col] = res[row]
    return state

def inv_mix_columns(state) :

    for col in range(4) :
        column = [state[row][col] for row in range(4)]

        res = mix_single_column(column,InvMixer)

        for row in range(4) :
            state[row][col] = res[row]
    return state

def add_round_key(state,round_key) :
    for row in range(4) :
        for col in range(4) :
            state[row][col] ^= round_key[row][col]
    return state


def rot_word(word:list) :
    word =  word[1:] + word[:1]
    return word


def sub_byte(word:list) :
    word = [Sbox[b] for b in word]
    return word



def key_expansion(key: bytes) : 

    Nk,Nr = KEY_SCHEDULE[len(key)]
    exp_words = 4*(Nr+1)

    words = []
    for i in range(Nk):
        words.append(list(key[4*i: 4*i+4]))
 
    for i in range(Nk, exp_words):
        temp = words[i - 1]
        if i % Nk == 0:
            temp = sub_byte(rot_word(temp))
            temp = [temp[0] ^ Rcon[i // Nk],temp[1],temp[2],temp[3]]
        elif Nk > 6 and i % Nk == 4 :
            temp = sub_byte(temp)
        words.append([words[i-4][b] ^ temp[b] for b in range(4)])
 
    return words

def get_round_key_matrix(words, numr) :

    cols = words[4*numr : 4*numr+4]
    matrix = [[0]*4 for _ in range(4)]

    for c,word in  enumerate(cols) :
        for r in range(4) :
            matrix[r][c] = word[r]
    return matrix


def encrypt_block(block, words) :
    Nr = len(words)//4 -1

    state = byte_to_state(block)

    state = add_round_key(state,get_round_key_matrix(words,0))

    for i in range(1,Nr+1) :
        state = sub_bytes(state)
        state = shift_row(state)
        if i!=Nr:
            state = mix_columns(state)
        state = add_round_key(state,get_round_key_matrix(words,i))
    
    return state_to_byte(state)

def decrypt_block(block, words):
    Nr = len(words)//4-1
    state = byte_to_state(block)

    state = add_round_key(state,get_round_key_matrix(words, Nr))

    for i in range(Nr-1,-1,-1):
        state = inv_shift_row(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state,get_round_key_matrix(words, i))
        if i != 0:
            state = inv_mix_columns(state)

    return state_to_byte(state)


def pad(data:bytes) :

    pad_len = BLOCK_SIZE - (len(data)%BLOCK_SIZE)

    return data + bytes([pad_len]) * pad_len

def unpad(data:bytes) :

    pad_len = data[len(data)-1]
    return data[:-pad_len]

def normalize_key(key_input: bytes, size_bytes=BLOCK_SIZE) :
 
    if len(key_input) >= size_bytes:
        return key_input[:size_bytes]
    return key_input + bytes(size_bytes - len(key_input)) 


def ecb_encrypt(plaintext:bytes,key:bytes, words=None) :

    if words is None:
        words = key_expansion(key)

    padded_text = pad(plaintext)

    out = bytearray()

    for i in range(0,len(padded_text),BLOCK_SIZE) :
        out+= encrypt_block(padded_text[i:i+BLOCK_SIZE], words)

    return bytes(out)

def ecb_decrypt(cypher_text:bytes,key:bytes, words=None) :
    if words is None:
        words = key_expansion(key)

    plain_text = bytearray()

    for i in range(0,len(cypher_text),BLOCK_SIZE) :
        plain_text += decrypt_block(cypher_text[i:i+BLOCK_SIZE],words)

    return unpad(bytes(plain_text))

def  cbc_encrypt(plain_text:bytes,key:bytes, words=None) :
    if words is None:
        words = key_expansion(key)
    iv = os.urandom(BLOCK_SIZE)
    padded_text = pad(plain_text)

    out = bytearray(iv)
    prev = iv

    for i in range(0,len(padded_text),BLOCK_SIZE) :
        block = padded_text[i:i+BLOCK_SIZE]
        xored = bytes(a^b for a,b in zip(block,prev))
        cypher= encrypt_block(xored,words)
        out += cypher
        prev = cypher
    return bytes(out)

def cbc_decrypt(cypher_text:bytes, key:bytes, words=None) :
    
    if words is None:
        words = key_expansion(key)
    iv = cypher_text[:BLOCK_SIZE]
    cypher_block = cypher_text[BLOCK_SIZE:]

    out = bytearray()
    prev = iv 

    for i in range(0,len(cypher_block),BLOCK_SIZE) :
        cypher = cypher_block[i:i+BLOCK_SIZE]
        block = decrypt_block(cypher,words)
        xored = bytes(a^b for a,b in zip(prev,block))
        out += xored
        prev = cypher

    return unpad(bytes(out))


def hex_str(b: bytes):
    return " ".join(f"{byte:02x}" for byte in b)
 
 
def demo(mode: str, key_ascii: str, plaintext_ascii: str, key_bits: int = 128):
    key = normalize_key(key_ascii.encode(), size_bytes=key_bits // 8)
    plaintext = plaintext_ascii.encode()
 
    print(f"AES-{key_bits} / {mode.upper()}:=")
    print("")
    print("Key=:")
    print(f"In ASCII: {key_ascii}")
    print(f"In HEX: {hex_str(key)}")
    print("")
    print("Plain Text:")
    print(f"In ASCII: {plaintext_ascii}")
    print(f"In HEX: {hex_str(plaintext)}")
    padded = pad(plaintext)
    print(f"In ASCII (After Padding): {padded.decode('latin-1')}")
    print(f"In HEX (After Padding): {hex_str(padded)}")
 
    t0 = time.perf_counter()
    words = key_expansion(key)
    t1 = time.perf_counter()
 
    t2 = time.perf_counter()
    if mode == "ecb":
        ciphertext = ecb_encrypt(plaintext, key, words=words)
    else:
        ciphertext = cbc_encrypt(plaintext, key, words=words)
    t3 = time.perf_counter()
    print("")
    print("Ciphered Text:")
    if mode == "cbc":
        print("CBC MODE:=")
    print(f"In HEX: {hex_str(ciphertext)}")
    print(f"In ASCII: {ciphertext.decode('latin-1')}")
 
    t4 = time.perf_counter()
    if mode == "ecb":
        recovered = ecb_decrypt(ciphertext, key, words=words)
    else:
        recovered = cbc_decrypt(ciphertext, key, words=words)
    t5 = time.perf_counter()
    print(" ")
    print("Deciphered Text:")
    print(f"After Unpadding:\nIn ASCII: {recovered.decode()}")
    print(f"In HEX: {hex_str(recovered)}")
 
    print("\nExecution Time Details:")
    print(f"Key Schedule Time: {(t1 - t0) * 1000} ms")
    print(f"Encryption Time: {(t3 - t2) * 1000} ms")
    print(f"Decryption Time: {(t5 - t4) * 1000} ms")
 
 
if __name__ == "__main__":
    demo("ecb", "BUET CSE21 Batch", "We need picnic")
    demo("cbc", "BUET CSE21 Batch", "We need picnic")
    







        








 






