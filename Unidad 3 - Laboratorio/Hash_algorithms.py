import struct

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
    
    def __repr__(self):
        if self.message:
            return f"{self.__class__.__name__}('{self.message.decode()}')"
        return f"{self.__class__.__name__}()"
    
    def __str__(self):
        return self.hexdigest()
    
    def __eq__(self, other):
        return self.h == other.h
    
    def digest_bytes(self):
        return struct.pack("<4L", *self.h)
    
    def digest_hex_bytes(self):
        return self.hexdigest().encode()
    
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
    
def main():
    message = b"The quick brown fox jumps over the lazy dog"
    md4 = MD4(message)
    print(f"MD4('{message.decode()}') = {md4.hexdigest()}")
    
if __name__ == "__main__":
    main()