import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class NCA:
    def __init__(self, file_path):
        self.file_path = file_path
        self.plain_txt = self.__get_plain_text()
        self.PRS = self.__gen_PRS(self.__get_seq_len())
        self.ops = self.__get_ops(len(self.plain_txt))
    
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

    def __get_plain_txt_len(self):
        with open(self.file_path, 'r') as file:
            return len(file.read())
    
    def __get_plain_text(self):
        with open(self.file_path, 'r') as file:
            return str(file.read())

    def __get_seq_len(self):
        with open(self.file_path, 'r') as file:
            return 2*(len(file.read())*3) + len(file.read()) + 7
        
    def __get_ops(self, plain_txt_len: int):
        ops = []
        ops.append(int(self.PRS[:7]) % 7)
        for i in range(1, plain_txt_len):
            ops.append(281*ops[i-1] + 443)

        return ops

    def __get_encoded_wo_shuffle(self):
        enc_wo_s = []
        for i in range(len(self.plain_txt)):
            ascii_val = int(self.plain_txt[i])
            chunk = int(self.PRS[7+i] + self.PRS[7+i+1] + self.PRS[7+i+2]) # 7 goes for the op
            enc_wo_s.append(ascii_val + (chunk))


    def encrypt(self):
        seq_len = self.__get_seq_len(self.file_path)
        self.__gen_PRS(seq_len)


if __name__ == '__main__':
    nca = NCA('plain.txt')
    plain_txt_len = nca._NCA__get_plain_txt_len()
    print(plain_txt_len)
    seq_len = nca._NCA__get_seq_len()
    print(seq_len)
    print("-------------------")
    nca._NCA__gen_PRS(seq_len)
    print(nca.PRS[:7])
    ops = nca._NCA__get_ops(plain_txt_len)
    print(ops)