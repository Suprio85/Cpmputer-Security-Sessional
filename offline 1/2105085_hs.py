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

def find_generator(P: int) -> int:
    q = (P - 1) // 2
    while True:
        g = random.randrange(2, P - 1)
        if pow(g, 2, P) == 1:
            continue
        if pow(g, q, P) == 1:
            continue
        return g
            

 
