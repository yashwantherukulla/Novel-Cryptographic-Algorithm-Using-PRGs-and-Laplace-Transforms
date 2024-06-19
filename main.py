import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class NCA:
    def __init__(self):
        self.PRS = 0
    
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
            self.PRS = prn_str[:seq_len]

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
            
            self.PRS = ''.join(prns)[:seq_len]

    def __get_plain_txt_len(self, file_path: str):
        with open(file_path, 'r') as file:
            return len(file.read())

    def __get_seq_len(self, file_path: str):
        with open(file_path, 'r') as file:
            return 2*(len(file.read())*3) + len(file.read()) + 7
        
    def __get_ops(self, plain_txt_len: int):
        ops = []
        ops.append(int(self.PRS[:7]) % 7)
        for i in range(1, plain_txt_len):
            ops.append(281*ops[i-1] + 443)

        return ops
    
    def encrypt(self, file_path: str):
        seq_len = self.__get_seq_len(file_path)
        self.__gen_PRS(seq_len)


if __name__ == '__main__':
    nca = NCA()
    plain_txt_len = nca._NCA__get_plain_txt_len('plain.txt')
    print(plain_txt_len)
    seq_len = nca._NCA__get_seq_len('plain.txt')
    print(seq_len)
    print("-------------------")
    nca._NCA__gen_PRS(seq_len)
    print(nca.PRS)
    ops = nca._NCA__get_ops(plain_txt_len)
    print(ops)