import hashlib
import random
import os
import time


def miller_rabin(n:int, k:int=20) :
    
    if n < 2 :
        return False
    
    small_p = [2,3,5,7,11,13,17,19,23,29,31,37,41]

    for p in small_p :
        if n == p : return True
        if n%p == 0 : return False

    
    r = 0
    d = n-1
    while d % 2 == 0 :
        r += 1
        d//= 2
    
  
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_safe_prime(bits: int) :
    
    while True:
        q = random.getrandbits(bits - 1) | 1 | (1 << (bits - 2)) 
        if miller_rabin(q):
            p = 2 * q + 1
            if miller_rabin(p):
                return p
            
            

def find_generator(P: int) :
    q = (P - 1) // 2
    while True:
        g = random.randrange(2, P - 1)
        if pow(g, 2, P) == 1:
            continue
        if pow(g, q, P) == 1:
            continue
        return g
    
def generate_public_params(bits: int, seed: int = 43):
    if seed is not None:
        random.seed(seed)
    P = generate_safe_prime(bits)
    g = find_generator(P)
    return P, g
 
def generate_private_public_key(P:int, g:int, bits:int):
    
    secret = random.getrandbits(bits) | (1 << (bits - 1))
    public = pow(g, secret, P)
    return secret, public
  
 
def derive_aes_key(shared_secret, key_bits):
    mask = (1 << key_bits) - 1
    key_int = shared_secret & mask
    return key_int.to_bytes(key_bits // 8)



def generate_private_public(P: int, g: int, bits: int):
    secret = random.getrandbits(bits) | (1 << (bits - 1))
    public = pow(g, secret, P)
    return secret, public
 
 
def compute_shared_secret(their_public: int, my_private: int, P: int):
    return pow(their_public, my_private, P)
 
 
def derive_aes_key(shared_secret, key_bits):
    mask = (1 << key_bits) - 1
    key_int = shared_secret & mask
    return key_int.to_bytes(key_bits // 8)
 
 
def run_single_exchange(bits: int, seed: int = 43) :
    if seed is not None:
        random.seed(seed)
 
    print(f"Diffie-Hellman Exchange, k = {bits} bits:=")
 
    P = generate_safe_prime(bits)
    g = find_generator(P)
    print(f"P = {P}")
    print(f"g = {g}")
 
    Ka, A = generate_private_public(P, g, bits)
    Kb, B = generate_private_public(P, g, bits)
    print(f"Alice's private key Ka = {Ka}")
    print(f"Alice's public key  A  = {A}")
    print(f"Bob's private key   Kb = {Kb}")
    print(f"Bob's public key    B  = {B}")
 
    s_alice = compute_shared_secret(B, Ka, P)
    s_bob = compute_shared_secret(A, Kb, P)
    print(f"Shared secret (Alice) = {s_alice}")
    print(f"Shared secret (Bob)   = {s_bob}")
 
    assert s_alice == s_bob, "Shared secrets do not match!"
    print("Shared secrets match: True")
 
    aes_key = derive_aes_key(s_alice, bits)
    print(f"Derived AES-{bits} key (hex) = {aes_key.hex()}")
    print()
 
 
def run_timing_table(trials: int = 5) -> None:
    print(" Timing Report (averaged over {} trials) ".format(trials))
    print(f"{'k':>5} | {'Time for A (ms)':>18} | {'Time for B (ms)':>18} | {'Time for s (ms)':>18}")
    print("-" * 68)
 
    for bits in (128, 192, 256):
        P = generate_safe_prime(bits)
        g = find_generator(P)
 
        total_a = total_b = total_s = 0.0
        for _ in range(trials):
            t0 = time.perf_counter()
            Ka, A = generate_private_public(P, g, bits)
            t1 = time.perf_counter()
 
            Kb, B = generate_private_public(P, g, bits)
            t2 = time.perf_counter()
 
            s_alice = compute_shared_secret(B, Ka, P)
            s_bob = compute_shared_secret(A, Kb, P)
            t3 = time.perf_counter()
 
            assert s_alice == s_bob, "Shared secrets do not match!"
 
            total_a += (t1 - t0)
            total_b += (t2 - t1)
            total_s += (t3 - t2)
 
        avg_a = total_a / trials * 1000
        avg_b = total_b / trials * 1000
        avg_s = total_s / trials * 1000
 
        print(f"{bits:>5} | {avg_a:>18.4f} | {avg_b:>18.4f} | {avg_s:>18.4f}")
    print()
 
 
if __name__ == "__main__":
    for bits in (128, 192, 256):
        run_single_exchange(bits, seed=406)
 
    run_timing_table(trials=5)

 
