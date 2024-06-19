import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import random
from math import factorial

class NCA:
    def __init__(self, file_path):
        self.file_path = file_path
        self.plain_txt = self.__get_plain_text()
        self.PRS = self.__gen_PRS(self.__get_seq_len())
        self.ops = self.__get_ops()
    
    def __gen_TRN(self):
        rb_size = secrets.token_bytes(1)
        rb_size = int.from_bytes(rb_size, 'big')
        random_bytes = secrets.token_bytes(rb_size//10) 
        return int.from_bytes(random_bytes, 'big')

    def __gen_PRS(self, seq_len: int):
        if seq_len < 4300 and seq_len > 0:
            seed = self.__gen_TRN()
            key = seed.to_bytes(32, 'big')
            nonce = (0).to_bytes(16, 'big')
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            prn = int.from_bytes(encryptor.update(b'\0' * (seq_len//2)), 'big')
            prn_str = str(prn)
            return prn_str[:seq_len]

        elif seq_len >= 4300:
            prns = []
            while len(''.join(prns)) < seq_len:
                seed = self.__gen_TRN()
                key = seed.to_bytes(32, 'big')
                nonce = (0).to_bytes(16, 'big')
                cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                prn = int.from_bytes(encryptor.update(b'\0' * (1000)), 'big')
                prn_str = str(prn)
                prns.append(prn_str)
            
            return ''.join(prns)[:seq_len]

    # def __get_plain_txt_len(self):
    #     with open(self.file_path, 'r') as file:
    #         return len(file.read())
    
    def __get_plain_text(self):
        with open(self.file_path, 'r') as file:
            return str(file.read())

    def __get_seq_len(self):
        with open(self.file_path, 'r') as file:
            return 2*(len(file.read())*3) + len(file.read()) + 7
        
    def __get_ops(self):
        ops = []
        plain_txt_len = len(self.plain_txt)
        ops.append(int(self.PRS[:7]) % 7)
        for i in range(1, plain_txt_len):
            ops.append(281*ops[i-1] + 443)

        return ops

    def __get_encoded_wo_shuffle(self):
        enc_wo_s = []
        skipped_chunks = 0
        for i in range(len(self.plain_txt)):
            chunk = int(self.PRS[7+i] + self.PRS[7+i+1] + self.PRS[7+i+2]) # 7 goes for the op
            if chunk!=0:
                ascii_val = ord(self.plain_txt[i])
                enc_wo_s.append(ascii_val + (chunk * self.ops[i]))
            else:
                skipped_chunks += 1
        
        return enc_wo_s, skipped_chunks
    
    def __get_shuffled(self, enc_wo_s: list, skipped_chunks: int):
        remaining_digits = self.PRS[:(7+len(self.plain_txt)+skipped_chunks)]
        shuffle_seed = int(remaining_digits) % factorial(len(self.plain_txt))
        
        random.seed(shuffle_seed)
        random.shuffle(enc_wo_s)
        enc_w_s = enc_wo_s
        return enc_w_s


    def encrypt(self):
        seq_len = self.__get_seq_len(self.file_path)
        self.__gen_PRS(seq_len)


if __name__ == '__main__':
    nca = NCA('plain.txt')
    # plain_txt_len = nca._NCA__get_plain_txt_len()
    # print(plain_txt_len)
    seq_len = nca._NCA__get_seq_len()
    print(seq_len)
    print("-------------------")
    nca._NCA__gen_PRS(seq_len)
    print(nca.PRS[:7])
    ops = nca._NCA__get_ops()
    print(ops)
    half_enc, skips = nca._NCA__get_encoded_wo_shuffle()
    print(half_enc, skips)
    shuffled = nca._NCA__get_shuffled(half_enc, skips)
    print(shuffled)