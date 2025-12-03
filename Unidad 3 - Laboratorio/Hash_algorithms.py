import struct
import math

"""Implementantion of hash algorithms."""

"""MD4 Hash Algorithm"""

class MD4:
    width = 32
    mask = 0xFFFFFFFF
    
    h = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476
    ]
    
    def __init__(self, message = None):
        if message is None:
            message = b""
        
        self.message = message
        
        ml = len(message) * 8
        message += b"\x80"
        message += b"\x00" * (-(len(message) + 8) % 64)
        message += struct.pack("<Q", ml)
        
        self._process_chunks([message[i : i + 64] for i in range(0, len(message), 64)])
    
    def digest_bytes(self):
        return struct.pack("<4L", *self.h)
    
    def hexdigest(self):
        return "".join(f"{value:02x}" for value in self.digest_bytes())
    
    def _process_chunks(self, chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I", chunk)), self.h.copy()
            
            shift_amounts_round1 = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = [x % 4 for x in range(-n, -n + 4)]
                K = n
                S = shift_amounts_round1[n % 4]
                hn = h[i] + MD4.auxiliary_function_f(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.left_rotate(hn & MD4.mask, S)

            shift_amounts_round2 = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = [x % 4 for x in range(-n, -n + 4)]
                K = n % 4 * 4 + n // 4
                S = shift_amounts_round2[n % 4]
                hn = h[i] + MD4.auxiliary_function_g(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.left_rotate(hn & MD4.mask, S)
            
            shift_amounts_round3 = [3, 9, 11, 15]
            key_schedule_round3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = [x % 4 for x in range(-n, -n + 4)]
                K = key_schedule_round3[n]
                S = shift_amounts_round3[n % 4]
                hn = h[i] + MD4.auxiliary_function_h(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.left_rotate(hn & MD4.mask, S)
            
            self.h = [(hv + hvn) & MD4.mask for hv, hvn in zip(self.h, h)]
    
    @staticmethod
    def auxiliary_function_f(x, y, z):
        return (x & y) | (~x & z)
    
    @staticmethod
    def auxiliary_function_g(x, y, z):
        return (x & y) | (x & z) | (y & z)
    
    @staticmethod
    def auxiliary_function_h(x, y, z):
        return x ^ y ^ z
    
    @staticmethod
    def left_rotate(value, amount):
        return ((value << amount) | (value >> (32 - amount))) & MD4.mask
    
"""MD5 Hash Algorithm"""

class MD5:
    h = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476
    ]
    
    rotate_amounts = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ]
    
    constants = [int(abs(math.sin(i + 1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]
    
    def __init__(self, message = None):
        if message is None:
            message = b""
        
        if isinstance(message, str):
            message = message.encode("ascii")
        
        self.message = message
        
        ml = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
        message = bytearray(message)
        message.append(0x80)
        
        while len(message) % 64 != 56:
            message.append(0)
        
        message += ml.to_bytes(8, byteorder='little')
        
        self._process([message[i : i + 64] for i in range(0, len(message), 64)])
    
    def bytes(self):
        return struct.pack("<4L", *self.h)
    
    def hexdigest(self):
        return "".join(f"{value:02x}" for value in self.bytes())
    
    def _process(self, chunks):
        for chunk in chunks:
            A, B, C, D = self.h
            X = list(struct.unpack("<16I", chunk))
            
            for i in range(64):
                if i < 16:
                    F = (B & C) | (~B & D)
                    g = i
                elif i < 32:
                    F = (D & B) | (~D & C)
                    g = (5 * i + 1) % 16
                elif i < 48:
                    F = B ^ C ^ D
                    g = (3 * i + 5) % 16
                else:
                    F = C ^ (B | ~D)
                    g = (7 * i) % 16
                
                to_rotate = (A + F + self.constants[i] + X[g]) & 0xFFFFFFFF
                new_B = (B + self.left_rotate(to_rotate, self.rotate_amounts[i])) & 0xFFFFFFFF
                
                A, B, C, D = D, new_B, B, C
            
            self.h[0] = (self.h[0] + A) & 0xFFFFFFFF
            self.h[1] = (self.h[1] + B) & 0xFFFFFFFF
            self.h[2] = (self.h[2] + C) & 0xFFFFFFFF
            self.h[3] = (self.h[3] + D) & 0xFFFFFFFF
        
    @staticmethod
    def left_rotate(value, amount):
        value &= 0xFFFFFFFF
        return (value << amount | value >> (32 - amount)) & 0xFFFFFFFF

"""SHA-1 Hash Algorithm"""

class SHA1:
    entry_constants = [
        [0x5a827999] * 20 +
        [0x6ed9eba1] * 20 +
        [0x8f1bbcdc] * 20 +
        [0xca62c1d6] * 20
    ]
    
    def __init__(self, message = None):
        if message is None:
            message = b""
        
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        self.message = message
        self.hash_constants = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
        
        ml = len(message) * 8
        message = bytearray(message)
        message.append(0x80)
        
        while len(message) % 64 != 56:
            message.append(0)
        
        message += ml.to_bytes(8, byteorder='big')
        
        self._process([message[i : i + 64] for i in range(0, len(message), 64)])
    
    def bytes(self):
        return struct.pack(">5I", *self.hash_constants)
    
    def hexdigest(self):
        return "".join(f"{value:08x}" for value in self.hash_constants)
    
    def _process(self, chunks):
        for chunk in chunks:
            w = list(struct.unpack(">16I", chunk))
            
            for i in range(16, 80):
                w.append(self.left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
            
            a, b, c, d, e = self.hash_constants
            
            for i in range(80):
                if i < 20:
                    f = (b & c) | (~b & d)
                elif i < 40:
                    f = b ^ c ^ d
                elif i < 60:
                    f = (b & c) | (b & d) | (c & d)
                else:
                    f = b ^ c ^ d
                
                temp = (self.left_rotate(a, 5) + f + e + self.entry_constants[0][i] + w[i]) & 0xFFFFFFFF
                e = d
                d = c
                c = self.left_rotate(b, 30)
                b = a
                a = temp
            
            self.hash_constants[0] = (self.hash_constants[0] + a) & 0xFFFFFFFF
            self.hash_constants[1] = (self.hash_constants[1] + b) & 0xFFFFFFFF
            self.hash_constants[2] = (self.hash_constants[2] + c) & 0xFFFFFFFF
            self.hash_constants[3] = (self.hash_constants[3] + d) & 0xFFFFFFFF
            self.hash_constants[4] = (self.hash_constants[4] + e) & 0xFFFFFFFF
        
    @staticmethod
    def left_rotate(value, amount):
        value &= 0xFFFFFFFF
        return (value << amount | value >> (32 - amount)) & 0xFFFFFFFF
    
"""SHA-256 Hash Algorithm"""

class SHA256:
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    def __init__(self, message=None):
        if message is None:
            message = b""
        
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        self.message = message
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        ml = len(message) * 8
        message = bytearray(message)
        message.append(0x80)
        
        while len(message) % 64 != 56:
            message.append(0)
        
        message += ml.to_bytes(8, byteorder='big')
        
        self._process([message[i:i + 64] for i in range(0, len(message), 64)])
    
    def bytes(self):
        return struct.pack(">8I", *self.h)
    
    def hexdigest(self):
        return "".join(f"{value:08x}" for value in self.h)
    
    def _process(self, chunks):
        for chunk in chunks:
            w = list(struct.unpack(">16I", chunk))
            
            for i in range(16, 64):
                s0 = self.right_rotate(w[i - 15], 7) ^ self.right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
                s1 = self.right_rotate(w[i - 2], 17) ^ self.right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
            
            a, b, c, d, e, f, g, h = self.h
            
            for i in range(64):
                S1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
                ch = (e & f) ^ (~e & g)
                temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
                S0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xFFFFFFFF
                
                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF
            
            self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
            self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
            self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
            self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
            self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
            self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
            self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
            self.h[7] = (self.h[7] + h) & 0xFFFFFFFF
    
    @staticmethod
    def right_rotate(value, amount):
        value &= 0xFFFFFFFF
        return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF
    
"""HMAC (Hash-based Message Authentication Code)"""

class HMAC:
    def __init__(self, key, message=None, hash_class=SHA256):
        if message is None:
            message = b""
        
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        self.hash_class = hash_class
        self.block_size = 64  
        
        if len(key) > self.block_size:
            key = hash_class(key).bytes()
        
        if len(key) < self.block_size:
            key = key + (b"\x00" * (self.block_size - len(key)))
        
        o_key_pad = bytes([k ^ 0x5C for k in key])
        i_key_pad = bytes([k ^ 0x36 for k in key])
        
        inner_hash = hash_class(i_key_pad + message).bytes()
        self.hash_result = hash_class(o_key_pad + inner_hash)
    
    def bytes(self):
        return self.hash_result.bytes()
    
    def hexdigest(self):
        return self.hash_result.hexdigest()
    
"""SHA-224 Hash Algorithm (variante de SHA-256)"""

class SHA224:
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    def __init__(self, message=None):
        if message is None:
            message = b""
        
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        self.message = message
        self.h = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ]
        
        ml = len(message) * 8
        message = bytearray(message)
        message.append(0x80)
        
        while len(message) % 64 != 56:
            message.append(0)
        
        message += ml.to_bytes(8, byteorder='big')
        
        self._process([message[i:i + 64] for i in range(0, len(message), 64)])
    
    def bytes(self):
        return struct.pack(">7I", *self.h[:7])
    
    def hexdigest(self):
        return "".join(f"{value:08x}" for value in self.h[:7])
    
    def _process(self, chunks):
        for chunk in chunks:
            w = list(struct.unpack(">16I", chunk))
            
            for i in range(16, 64):
                s0 = self.right_rotate(w[i - 15], 7) ^ self.right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
                s1 = self.right_rotate(w[i - 2], 17) ^ self.right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
            
            a, b, c, d, e, f, g, h = self.h
            
            for i in range(64):
                S1 = self.right_rotate(e, 6) ^ self.right_rotate(e, 11) ^ self.right_rotate(e, 25)
                ch = (e & f) ^ (~e & g)
                temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
                S0 = self.right_rotate(a, 2) ^ self.right_rotate(a, 13) ^ self.right_rotate(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xFFFFFFFF
                
                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF
            
            self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
            self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
            self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
            self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
            self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
            self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
            self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
            self.h[7] = (self.h[7] + h) & 0xFFFFFFFF
    
    @staticmethod
    def right_rotate(value, amount):
        value &= 0xFFFFFFFF
        return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

def main():
    message = b"The quick brown fox jumps over the lazy dog"
    md4 = MD4(message)
    md5 = MD5(message)
    sha1 = SHA1(message)
    sha256 = SHA256(message)
    sha224 = SHA224(message)
    print(f"MD4('{message.decode()}') = {md4.hexdigest()}")
    print(f"MD5('{message.decode()}') = {md5.hexdigest()}")
    print(f"SHA1('{message.decode()}') = {sha1.hexdigest()}")
    print(f"SHA256('{message.decode()}') = {sha256.hexdigest()}")
    print(f"SHA224('{message.decode()}') = {sha224.hexdigest()}")
    
    # HMAC example
    key = b"secret_key"
    hmac = HMAC(key, message)
    print(f"HMAC-{hmac.hash_class.__name__}(key='{key.decode()}', message='{message.decode()}') = {hmac.hexdigest()}")
    
if __name__ == "__main__":
    main()