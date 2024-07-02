from Encryptor import Encryptor
from math import factorial
import random

import numpy as np

class Decryptor(Encryptor):
    def __init__(self, file_path, fn_str, op_param:tuple, quotients:list, ):
        self.file_path = file_path
        self.w = op_param[0]
        self.b = op_param[1]
        self.fn_str = fn_str
        self.quotients = quotients
        self.cipher_text = self._Encryptor__get_text_from_file()
        self.PRS = self._Encryptor__gen_PRS(self._Encryptor__get_seq_len())
        self.ops = self.__get_ops()

    def __get_num_from_cipher_txt(self):
        ct_arr = list(self.cipher_text)
        for i in range(len(ct_arr)):
            ct_arr[i] = ord(ct_arr[i]) - 33
            
        return ct_arr
    
    def __get_ops(self):
        ops = []
        cipher_txt_len = len(self.cipher_text)
        ops.append(int(self.PRS[:7]) % 7)
        for i in range(1, cipher_txt_len):
            ops.append((self.w)*ops[i-1] + self.b)
        
        ops = np.array(ops)
        return ops
    
    def __get_chunks_for_decoding(self, test:bool=True):
        self.PRS = "1234567000123456789012345678"
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
        shuff_seed = int(self.__get_remaining_digits_for_shuffle(skips)) % factorial(len(self.cipher_text))
        random.seed(shuff_seed)
        random.shuffle(arr)
        return arr
    

    def decrypt(self):
        ct_arr = list(self.cipher_text)
        for i in range(len(ct_arr)):
            ct_arr[i] = ord(ct_arr[i]) - 33
        ct_arr = np.array(ct_arr)

        q = np.array(self.quotients)
        dec_shuff = 94*q + ct_arr
        print(dec_shuff)

        lt_co_eff = np.array(self._Encryptor__get_laplace_co_effs(len(dec_shuff)))
        G_prime = dec_shuff * lt_co_eff

        print(G_prime)

        chunks, skips = self.__get_chunks_for_decoding()
        print(chunks)
        print(skips)

        dec_no_shuff = self.__get_rev_shuffled(G_prime, skips)
        dec_no_shuff = np.array(dec_no_shuff)
        print(dec_no_shuff)

        M = dec_no_shuff - np.array(self.ops)*np.array(chunks)
        
        print(self.ops)
        print(chunks)

        print(M)
        
        





if __name__ == "__main__":
    r = 2
    fn = f"x*exp({r}*x)"
    q = [7, 2449, 268643]

    d = Decryptor("cipher_text.txt", fn, (173, 833), q)
    d.decrypt()
