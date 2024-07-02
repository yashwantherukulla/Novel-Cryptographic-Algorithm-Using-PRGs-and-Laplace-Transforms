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


class Encryptor:
    def __init__(self, file_path, fn_str, op_param:tuple):
        self.file_path = file_path
        self.w = op_param[0]
        self.b = op_param[1]
        self.fn_str = fn_str
        self.cipher_txt = self.__get_text_from_file()
        # print(self.__get_seq_len())
        self.PRS = self.__gen_PRS(self.__get_seq_len())
        # self.PRS = "7101901153000972121087318"
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
            length = 0
            if prn > 0:
                length = int(log10(prn)) + 1
            elif prn == 0:
                length = 1
            else:
                length = int(log10(-prn)) + 1
            # print(length)
            # prn_str = str(prn)
            # return prn_str[:seq_len]
            length_difference = length - seq_len

            if length_difference > 0:
                prn = prn // (10 ** length_difference)
                
            return str(prn)


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
            
            PRS_no_XOR =  ''.join(prns)[:seq_len]
            # add a part where PRS_no_XOR is XORed with the ascii values of the plain text
            # PRS = int(PRS_no_XOR) ^ int(self.plain_txt)
            # return str(PRS)


    def __get_text_from_file(self):
        with open(self.file_path, 'r') as file:
            return str(file.read())

    def __get_seq_len(self):
        with open(self.file_path, 'r') as file:
            txt_len = len(file.read())
            seq_len = txt_len*7 + 7
            return seq_len
        
    def __get_ops(self):
        ops = []
        plain_txt_len = len(self.cipher_txt)
        ops.append(int(self.PRS[:7]) % 7)
        for i in range(1, plain_txt_len):
            ops.append((self.w)*ops[i-1] + self.b)

        return ops

    def __get_decoded_wo_shuffle(self, test:bool=False):
        enc_wo_s = []
        skipped_chunks = 0
        i=0
        while len(enc_wo_s)<len(self.cipher_txt):
            chunk = str(self.PRS[7+(3*i)] + self.PRS[7+(3*i+1)] + self.PRS[7+(3*i+2)]) # 7 goes for the op
            if test:
                print(f"chunk {i} : {chunk} ===> used : {bool(chunk!='000')}")
            
            if chunk!="000":
                chunk = int(chunk)
                ascii_val = ord(self.cipher_txt[i-skipped_chunks])
                enc_wo_s.append(ascii_val + (chunk * self.ops[i-skipped_chunks]))
            else:
                skipped_chunks += 1
            i+=1
        
        return enc_wo_s, skipped_chunks
    
    def __get_shuffled(self, enc_wo_s: list, skipped_chunks: int):
        remaining_digits = self.PRS[:(7+len(self.cipher_txt)+skipped_chunks)]
        # print(len(remaining_digits))
        shuffle_seed = int(int(remaining_digits[:4300]) % factorial(len(self.cipher_txt)))
        
        random.seed(shuffle_seed)
        random.shuffle(enc_wo_s)
        enc_w_s = enc_wo_s
        return enc_w_s
    
    def __mclaurin_exp(self, n:int):
        x = symbols('x')
        fn = sympify(self.fn_str)

        expansion = fn.subs(x, 0) #f(0)
        for i in range(1, n+1):
            derivative = diff(fn, x, i).subs(x, 0)
            expansion += (derivative * x**i)/ factorial(i)
        
        return expansion
    
    def __laplace_trans(self, mc_exp: sympy.core.add.Add):
        lt = laplace_transform(mc_exp, x, s)
        return lt

    def __get_laplace_co_effs(self, n:int):
        mc_exp = self.__mclaurin_exp(n)
        lt = self.__laplace_trans(mc_exp)[0]
        coeffs = []
        
        for term in lt.as_ordered_terms():
            coeff = term.as_coeff_mul(s)[0]
            coeffs.append(coeff)

        return coeffs

    def encrypt(self):
        enc_no_shuff, skips = self.__get_decoded_wo_shuffle()
        # print('1')
        enc_shuff = self.__get_shuffled(enc_no_shuff, skips)
        # print('2')
        enc_shuff = np.array(enc_shuff)
        # print(np.where(enc_shuff==0))
        # print('3')
        lt_co_eff = self.__get_laplace_co_effs(len(enc_shuff))
        # print('4')
        lt_co_eff = np.array(lt_co_eff)
        # print(np.where(lt_co_eff==0))
        # print('5')
        enc_arr = enc_shuff * lt_co_eff
        # print('6')
        # print(enc_shuff)
        # print(lt_co_eff)
        # print(enc_arr)

        all_Q = []
        cipher_text = ""
        # print(len(enc_arr)) # enc_arr is missing 1 character from the og plain text
        for i in enc_arr:
            R = i%94
            Q = i//94
            letter = chr(R+33)
            all_Q.append(Q)
            cipher_text += letter
            # print(len(all_Q))

        # print('done')
        return cipher_text, all_Q


    def encrypt_test(self):
        self.PRS = "1234567000123456789012345678"
        self.w = 21
        self.b = 21
        self.cipher_txt = "sir"
        self.ops = self.__get_ops()

        print('plain text : ' + self.cipher_txt)
        print(f"w : {self.w}")
        print(f"b : {self.b}")
        print(f"--------------------")
        print(f"Pseudo Random Sequence : {self.PRS}")
        print(f"all operators : {self.ops}")

        print("--------------------")

        enc_no_shuff, skips = self.__get_decoded_wo_shuffle(test=True)
        print(f"enc_no_shuff : {enc_no_shuff}")
        print(f"#skipped chunks : {skips}")
        
        enc_shuff = self.__get_shuffled(enc_no_shuff, skips)
        enc_shuff = np.array(enc_shuff)
        print(f"enc_shuff : {enc_shuff}")
        print(f"length of enc_shuff : {len(enc_shuff)}")
        
        lt_co_eff = self.__get_laplace_co_effs(len(enc_shuff))
        lt_co_eff = np.array(lt_co_eff)
        print(f"all laplace co-eff : {lt_co_eff}")

        enc_arr = enc_shuff * lt_co_eff
        print(f"enc_arr : {enc_arr}")

        all_Q = []
        cipher_text = ""
        for i in enc_arr:
            R = i%94
            Q = i//94
            letter = chr(R+33)
            all_Q.append(Q)
            cipher_text += letter

        print(f"cipher_text : {cipher_text}")
        print(f"all_Q : {all_Q}")


if __name__ == '__main__':
    # plain_txt_len = nca._NCA__get_plain_txt_len()
    # print(plain_txt_len)
    # seq_len = nca._NCA__get_seq_len()
    # print(seq_len)
    # print("-------------------")
    # nca._NCA__gen_PRS(seq_len)
    # print(nca.PRS[:7])
    # ops = nca._NCA__get_ops()
    # print(ops)
    # half_enc, skips = nca._NCA__get_encoded_wo_shuffle()
    # print(half_enc, skips)
    # shuffled = nca._NCA__get_shuffled(half_enc, skips)
    # print(shuffled)

    r = 2

    fn = f"x*exp({r}*x)"
    
    nca = Encryptor('plain.txt', fn, (173, 833))
    # mc_exp = nca._NCA__mclaurin_exp(fn, n)
    # print(mc_exp)
    # lt = nca._NCA__laplace_trans(mc_exp)[0]
    # print(lt , type(lt))
    # lt_coeff = nca._NCA__get_laplace_co_effs(fn, n)
    # print(lt_coeff)
    # ct, qs = nca.encrypt()
    # # print(ct)
    # # print(qs)
    # with open('cipher_text.txt', 'w') as file:
    #     file.write(ct)

    nca.encrypt_test()