#Decryptor.py
import random
from math import factorial
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import sympy
from sympy import symbols, diff, factorial, sympify
from sympy.integrals import laplace_transform
from sympy.abc import x, s
import numpy as np
from typing import Tuple, List, Dict

class Decryptor:
    def __init__(self, file_path: str, fn_str: str, op_param: Tuple[int, int, int], PRS_seed: int, quotients: List[int]):
        self.file_path = file_path
        self.init_op_param, self.w, self.b = op_param
        self.fn_str = fn_str
        self.cipher_text = self.__get_text_from_file()
        self.PRS_seed = PRS_seed
        self.quotients = quotients
        self.PRS = self.__gen_PRS(self.__get_seq_len())
        self.ops = self.__get_ops()

    def __get_text_from_file(self) -> str:
        with open(self.file_path, 'r') as file:
            return file.read()

    def __get_seq_len(self) -> int:
        return len(self.cipher_text) * 7 + self.init_op_param

    def __gen_PRS(self, seq_len: int) -> str:
        if seq_len < 4300 and seq_len > 0:
            key = self.PRS_seed.to_bytes(32, 'big')
            nonce = bytes(16)
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            prn = int.from_bytes(encryptor.update(bytes(seq_len // 2)), 'big')
            
            prn_str = str(abs(prn))
            if len(prn_str) > seq_len:
                return prn_str[:seq_len]
            return prn_str.zfill(seq_len)
        else:
            raise ValueError("Sequence length must be between 1 and 4299")

    def __get_ops(self) -> List[int]:
        cipher_txt_len = len(self.cipher_text)
        ops = [0] * cipher_txt_len
        ops[0] = (int(self.PRS[:self.init_op_param]) % self.init_op_param) + 1
        for i in range(1, cipher_txt_len):
            ops[i] = (self.w * ops[i-1] + self.b) % (2**32)
        return ops

    def __get_chunks_for_decoding(self) -> Tuple[List[int], int]:
        chunks = []
        skipped_chunks = 0
        i = 0
        while len(chunks) < len(self.cipher_text):
            chunk = self.PRS[self.init_op_param+(3*i):self.init_op_param+(3*i+3)]
            if chunk != "000":
                chunks.append(int(chunk))
            else:
                skipped_chunks += 1
            i += 1
        return chunks, skipped_chunks

    def __get_unshuffled(self, arr: List[int], skipped_chunks: int) -> List[int]:
        remaining_digits = self.PRS[(self.init_op_param+3*(len(self.cipher_text)+skipped_chunks)):]
        shuffle_seed = int(int(remaining_digits[:4300]) % factorial(len(self.cipher_text)) + 1)
        random.seed(shuffle_seed)
        indices = list(range(len(arr)))
        random.shuffle(indices)
        return [arr[indices.index(i)] for i in range(len(arr))]

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

    def decrypt(self) -> str:
        # Step 1: Reconstruct the encrypted array
        remainders = np.array([ord(c) - 33 for c in self.cipher_text])
        enc_arr = np.array(self.quotients) * 94 + remainders

        # Step 2: Undo the Laplace transform
        lt_co_eff = np.array(self.__get_laplace_co_effs(len(enc_arr)))
        dec_arr = enc_arr / lt_co_eff

        # Step 3: Undo the shuffling
        chunks, skipped_chunks = self.__get_chunks_for_decoding()
        unshuffled_arr = self.__get_unshuffled(dec_arr.tolist(), skipped_chunks)

        # Step 4: Undo the PRS-based encoding
        plain_chars = []
        j = 0
        for i, val in enumerate(unshuffled_arr):
            if chunks[i] != 0:  # Corresponding to chunk != "000" in encryption
                ascii_val = int(round(val - (chunks[i] * self.ops[j])))
                plain_chars.append(chr(ascii_val))
                j += 1

        return ''.join(plain_chars)

if __name__ == '__main__':
    r = 2
    fn = f"x*exp({r}*x)"
    
    with open('cipher.txt', 'r') as file:
        cipher_text = file.read()

    with open('PRS_seed.txt', 'r') as file:
        PRS_seed = int(file.read())
    
    with open('quotients.txt', 'r') as file:
        quotients = [int(x) for x in file.readlines()]

    decryptor = Decryptor('cipher.txt', fn, (157, 173, 833), PRS_seed, quotients)
    decrypted_text = decryptor.decrypt()

    print(f"Decrypted text: {decrypted_text[:50]}")

    with open('decrypted.txt', 'w') as file:
        file.write(decrypted_text)

    print("Decryption completed and saved to 'decrypted.txt'")