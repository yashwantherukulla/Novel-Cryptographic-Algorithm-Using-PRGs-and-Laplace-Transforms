from Encryptor import Encryptor
from math import factorial, log10
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

import numpy as np

class Decryptor(Encryptor):
    def __init__(self, file_path, fn_str, op_param:tuple, quotients:list, PRS_seed:int):
        self.file_path = file_path
        self.w = op_param[0]
        self.b = op_param[1]
        self.fn_str = fn_str
        self.quotients = quotients
        self.cipher_text = self._Encryptor__get_text_from_file()
        self.PRS = self.__gen_PRS(self._Encryptor__get_seq_len(), PRS_seed)
        self.ops = self.__get_ops()

    
    def __gen_PRS(self, seq_len: int, seed:int):
        if seq_len < 4300 and seq_len > 0:
            key = seed.to_bytes(32, 'big')
            nonce = (0).to_bytes(16, 'big')
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            prn = int.from_bytes(encryptor.update(b'\0' * (seq_len//2)), 'big')
            length = 0
            if prn > 0:
                length = int(log10(prn)) + 1
            elif prn == 0:
                length = 1
            else:
                length = int(log10(-prn)) + 1

            length_difference = length - seq_len

            if length_difference > 0:
                prn = prn // (10 ** length_difference)
                
            return str(prn)

    def __get_ops(self):
        ops = []
        cipher_txt_len = len(self.cipher_text)
        ops.append((int(self.PRS[:7]) % 7)+1)
        for i in range(1, cipher_txt_len):
            ops.append((self.w)*ops[i-1] + self.b)
        
        ops = np.array(ops)
        return ops
    
    def __get_chunks_for_decoding(self, test:bool=True):
        chunks = []
        skipped_chunks = 0
        i=0
        while len(chunks)<len(self.cipher_text):
            chunk = str(self.PRS[7+(3*i)] + self.PRS[7+(3*i+1)] + self.PRS[7+(3*i+2)]) # 7 goes for the op
            if test:
                print(f"chunk {i} : {chunk} ===> used : {bool(chunk!='000')}")
            
            if chunk!="000": 
                chunks.append(int(chunk))
            else:
                skipped_chunks += 1
            i+=1
        
        return chunks, skipped_chunks
    
    def __get_remaining_digits_for_shuffle(self, skipped_chunks:int):
        remaining_digits = self.PRS[(7+3*(len(self.cipher_text)+skipped_chunks)):]
        return remaining_digits

    def __get_rev_shuffled(self, arr, skips:int):
        shuff_seed = int(self.__get_remaining_digits_for_shuffle(skips)) % factorial(len(self.cipher_text)) + 1
        random.seed(shuff_seed)
        random.shuffle(arr)
        return arr
    

    def decrypt(self):
        ct_arr = list(self.cipher_text)
        for i in range(len(ct_arr)):
            ct_arr[i] = ord(ct_arr[i]) - 33
        ct_arr = np.array(ct_arr)

        q = np.array(self.quotients)
        G_prime = 94*q + ct_arr
        print(G_prime)

        lt_co_eff = np.array(self._Encryptor__get_laplace_co_effs(len(G_prime))) 
        print(lt_co_eff)
        G = G_prime / lt_co_eff

        print(G)

        chunks, skips = self.__get_chunks_for_decoding()
        print(chunks)
        print(skips)

        M_prime = self.__get_rev_shuffled(G, skips)
        M_prime = np.array(M_prime)
        print(M_prime)

        M = M_prime - np.array(self.ops)*np.array(chunks)
        print(f"{M} = {M_prime} - {self.ops} * {chunks}")
        M_chars = [chr(value) for value in M]
        print("".join(M_chars))
        
        





if __name__ == "__main__":
    r = 2
    fn = f"x*exp({r}*x)"
    q = [124596652, 12473450, 384608366121, 1408, 1330835]
    PRS_seed = 785141846963222137529018174297853022329490363615611506679

    d = Decryptor("cipher.txt", fn, (173, 833), q, PRS_seed)
    d.decrypt()
