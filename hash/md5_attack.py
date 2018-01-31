from binascii import unhexlify

class MD5:
    default_h0, default_h1, default_h2, default_h3 = \
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    def __init__(self, message, h0 = default_h0, h1 = default_h1, \
                 h2 = default_h2, h3 = default_h3, length = 0):

        self.K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

        self.s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

        self.h0, self.h1, self.h2, self.h3 = h0, h1, h2, h3

        if length == 0:
            length = len(message) * 8
        self.message = self._append_msg(message, length)
        
        for i in range(0, len(self.message), 64):
            self._handle(self.message[i:i+64])

    def _append_msg(self, message, length):
        
        message = bytearray(message)
        message.append(0x80)
        while len(message) % 64 != 56:
            message.append(0)
        length &= 0xffffffffffffffff 
        return message + length.to_bytes(8, byteorder='little')

    def _handle(self, chunk):
        
        lrot = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xffffffff
        
        a, b, c, d = self.h0, self.h1, self.h2, self.h3
        for i in range(64):
            if 0 <= i <= 15:
                f,g = (b & c) | (  (~b) & d), i
            elif 16 <= i <= 31:
                f,g = (b & d) | (c & (~d)), (5 * i + 1) % 16
            elif 32 <= i <= 47:
                f,g = b ^ c ^ d, (3 * i + 5) % 16
            elif 48 <= i <= 63:
                f,g = c ^ (b | ~d), (7 * i) % 16

            f = (f + a + self.K[i] + int.from_bytes(chunk[g*4:(g+1)*4], byteorder='little')) & 0xffffffff
            a, d, c, b = d & 0xffffffff, c & 0xffffffff, b & 0xffffffff, (b + lrot(f, self.s[i]))  & 0xffffffff
            

        self.h0 = (self.h0 + a) & 0xffffffff
        self.h1 = (self.h1 + b) & 0xffffffff
        self.h2 = (self.h2 + c) & 0xffffffff
        self.h3 = (self.h3 + d) & 0xffffffff
        
    def dec_digest(self):
        return  (self.h3 << 96) | (self.h2 << 64) | (self.h1 << 32) | self.h0
    def byte_digest(self):
        return self.dec_digest().to_bytes(16,byteorder='little')
    def digest(self):
        return '{:032x}'.format(int.from_bytes(self.byte_digest(),byteorder = 'big'))

def padMsg(keylen, message, padding):
    message = bytearray(message)
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    length = (keylen +  len(message)) & 0xffffffffffffffff 
    return bytes(message + length.to_bytes(8, byteorder='little') + bytearray(padding))

def forgeHash(message, padding, digest, padded_Hash):
    keylen = 1
    digest = unhexlify(digest)
    h0 = int.from_bytes(digest[:4],byteorder = 'little')
    h1 = int.from_bytes(digest[4:8],byteorder = 'little')
    h2 = int.from_bytes(digest[8:12],byteorder = 'little')
    h3 = int.from_bytes(digest[12:16],byteorder = 'little')
    while True:
        msg_padded = padMsg(keylen, message, padding)
        forge = MD5(padding, h0= h0, h1=h1, h2=h2, h3=h3, length=(len(msg_padded) + keylen) * 8).digest()
        if padded_Hash(msg_padded) == forge:
            print("[+] key length: {}".format(keylen))
            return forge
        keylen += 1

        if keylen >= 40:
            print("[-] Failed")
            return

if __name__ == "__main__":
    message = b"User=whocares&Admin=False"
    print(MD5(message).digest())


