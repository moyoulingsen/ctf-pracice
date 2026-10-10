import base64
import random
from tqdm import *

def multi_encode2(plaintext: str, iterations: int = 10000) -> str:

    data = plaintext.encode('utf-8')

    for _ in tqdm(range(iterations)):
        choice = random.choice(['b16', 'b32', 'b64'])
        if choice == 'b16':
            data = base64.b16encode(data)   
        elif choice == 'b32':
            data = base64.b32encode(data)
        else:  # b64
            data = base64.b64encode(data)
    return data.decode('utf-8')

def encrypt1(text: str, key: str) -> str:
    result = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)].upper()) - ord('A')
            new_ch = chr((ord(ch) - base + shift) % 26 + base)
            result.append(new_ch)
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def encrypt3(text: str, shift: int) -> str:
    res = []
    cur = shift
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            res.append(chr((ord(ch) - base + cur) % 26 + base))
        else:
            res.append(ch)
        cur += 1
    return ''.join(res)

m = '???'
key = '???'
text1 = encrypt1(m, key)

iterations = random.randint(1 , 100)
text2 = multi_encode2(text1, iterations)

shift = random.randint(1<<10 , 1<<30)
cipher = encrypt3(text2, shift)

with open('code.txt', 'w', encoding='utf-8') as f:
    f.write(cipher)