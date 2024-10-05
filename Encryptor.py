#Encryptor.py
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import random
from math import factorial, log10
import sympy
from sympy import symbols, diff, factorial, sympify
from sympy.integrals import laplace_transform
from sympy.abc import x, s
import numpy as np
from typing import Tuple, List, Dict

class Encryptor:
    def __init__(self, file_path: str, fn_str: str, op_param: Tuple[int, int]):
        self.file_path = file_path
        self.w, self.b = op_param
        self.fn_str = fn_str
        self.plain_txt = self.__get_text_from_file()
        self.PRS_seed = None
        self.PRS = self.__gen_PRS(self.__get_seq_len())
        self.ops = self.__get_ops()

    def __gen_TRN(self) -> int:
        rb_size = secrets.randbits(8) 
        return secrets.randbits(rb_size)

    def __gen_PRS(self, seq_len: int) -> str:
        if seq_len < 4300 and seq_len > 0:
            self.PRS_seed = self.__gen_TRN()
            key = self.PRS_seed.to_bytes(32, 'big')
            nonce = bytes(16)
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            prn = int.from_bytes(encryptor.update(bytes(seq_len // 2)), 'big')
        
            prn_str = str(abs(prn))
        
        # prn_str = ""
        # bytes_needed = (seq_len + 1) // 2  # Ensure enough bytes are generated
        # chunk_size = 1024  # Process in chunks to avoid large integer conversion
        
        # for _ in range(0, bytes_needed, chunk_size):
        #     chunk = encryptor.update(bytes(min(chunk_size, bytes_needed)))
        #     prn_str += str(abs(int.from_bytes(chunk, 'big')))
        #     bytes_needed -= chunk_size
        
            if len(prn_str) > seq_len:
                return prn_str[:seq_len]
            return prn_str.zfill(seq_len)
        else:
            raise ValueError("Sequence length must be between 1 and 4299")

    def __get_text_from_file(self) -> str:
        with open(self.file_path, 'r') as file:
            return file.read()

    def __get_seq_len(self) -> int:
        return len(self.plain_txt) * 7 + 7

    def __get_ops(self) -> List[int]:
        plain_txt_len = len(self.plain_txt)
        ops = [0] * plain_txt_len
        ops[0] = (int(self.PRS[:7]) % 7) + 1
        for i in range(1, plain_txt_len):
            ops[i] = (self.w * ops[i-1] + self.b) % (2**32) 
        return ops

    def __get_encoded_wo_shuffle(self) -> Tuple[List[int], int]:
        enc_wo_s = []
        skipped_chunks = 0
        i = 0
        while len(enc_wo_s) < len(self.plain_txt):
            chunk = self.PRS[7+(3*i):7+(3*i+3)]
            if chunk != "000":
                chunk = int(chunk)
                ascii_val = ord(self.plain_txt[i-skipped_chunks])
                enc_wo_s.append(ascii_val + (chunk * self.ops[i-skipped_chunks]))
            else:
                skipped_chunks += 1
            i += 1
        return enc_wo_s, skipped_chunks

    def __get_shuffled(self, enc_wo_s: List[int], skipped_chunks: int) -> List[int]:
        remaining_digits = self.PRS[(7+3*(len(self.plain_txt)+skipped_chunks)):]
        shuffle_seed = int(int(remaining_digits[:4300]) % factorial(len(self.plain_txt)) + 1)
        random.seed(shuffle_seed)
        enc_w_s = enc_wo_s.copy()
        random.shuffle(enc_w_s)
        return enc_w_s

    def __mclaurin_exp(self, n: int) -> sympy.core.add.Add:
        x = symbols('x')
        fn = sympify(self.fn_str)
        expansion = fn.subs(x, 0)
        for i in range(1, n+1):
            derivative = diff(fn, x, i).subs(x, 0)
            expansion += (derivative * x**i) / factorial(i)
        return expansion

    def __laplace_trans(self, mc_exp: sympy.core.add.Add) -> Tuple:
        return laplace_transform(mc_exp, x, s)

    def __get_laplace_co_effs(self, n: int) -> List[float]:
        mc_exp = self.__mclaurin_exp(n)
        lt = self.__laplace_trans(mc_exp)[0]
        return [float(term.as_coeff_mul(s)[0]) for term in lt.as_ordered_terms()]

    def encrypt(self, write_to_file: bool = True) -> Tuple[str, Dict]:
        enc_no_shuff, skips = self.__get_encoded_wo_shuffle()
        enc_shuff = self.__get_shuffled(enc_no_shuff, skips)
        enc_shuff = np.array(enc_shuff)
        lt_co_eff = np.array(self.__get_laplace_co_effs(len(enc_shuff)))
        enc_arr = enc_shuff * lt_co_eff

        all_Q = []
        cipher_text = ""
        
        for i in enc_arr:
            R = int(i % 94)
            Q = int(i // 94)
            letter = chr(R + 33)
            all_Q.append(Q)
            cipher_text += letter
        
        keys = {
            'PRS_seed': self.PRS_seed,
            'Quotients': all_Q,
        }

        if write_to_file:
            with open('cipher.txt', 'w') as file:
                file.write(cipher_text)

        return cipher_text, keys

if __name__ == '__main__':
    r = 2
    fn = f"x*exp({r}*x)"
    
    encryptor = Encryptor('plain.txt', fn, (173, 833))
    cipher_text, keys = encryptor.encrypt(True)

    print(f"Cipher text: {cipher_text[:50]}")
    print(f"PRS seed: {keys['PRS_seed']}")
    with open('PRS_seed.txt', 'w') as file:
        file.write(str(keys['PRS_seed']))
    print(f"quotients: {keys['Quotients'][:10]}")
    with open('quotients.txt', 'w') as file:
        for i in keys['Quotients']:
            file.write(str(i) + '\n')