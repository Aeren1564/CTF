import os, json
from PIL import Image, ImageFont, ImageDraw
import struct
import random
from collections import Counter

def s_substitute(m):
    s_box = {"0": "6", "1": "4", "2": "c", "3": "5", "4": "0", "5": "7", "6": "2", "7": "e", "8": "1", "9": "f", "a": "3", "b": "d", "c": "8", "d": "a", "e": "9", "f": "b"}
    return s_box[m]

def r_substitute(m):
    r_box = {"0": "4", "1": "8", "2": "6", "3": "a", "4": "1", "5": "3", "6": "0", "7": "5", "8": "c", "9": "e", "a": "d", "b": "f", "c": "2", "d": "b", "e": "7", "f": "9"}
    return r_box[m]

def shuffle_bytes(input_bytes, is_shuffle=True):
    res = b""
    for i in range(0, len(input_bytes), 16):
        b = input_bytes[i:i+16]
        shuffle_map = {2: {1: 0, 0: 1}, 3: {2: 0, 1: 1, 0: 2}, 4: {1: 0, 0: 1, 3: 2, 2: 3}, 5: {3: 0, 2: 1, 1: 2, 0: 3, 4: 4}, 6: {2: 0, 1: 1, 0: 2, 5: 3, 4: 4, 3: 5}, 7: {4: 0, 5: 1, 2: 2, 1: 3, 6: 4, 3: 5, 0: 6}, 8: {7: 0, 6: 1, 3: 2, 2: 3, 4: 4, 0: 5, 5: 6, 1: 7}, 9: {0: 6, 1: 0, 2: 5, 3: 1, 4: 2, 5: 4, 6: 8, 7: 3, 8: 7}, 10: {0: 3, 1: 6, 2: 0, 3: 9, 4: 1, 5: 7, 6: 4, 7: 5, 8: 8, 9: 2}, 11: {0: 8, 1: 2, 2: 1, 3: 10, 4: 0, 5: 3, 6: 7, 7: 6, 8: 5, 9: 4, 10: 9}, 12: {0: 1, 1: 5, 2: 7, 3: 11, 4: 8, 5: 10, 6: 6, 7: 0, 8: 3, 9: 9, 10: 4, 11: 2}, 13: {0: 3, 1: 9, 2: 11, 3: 6, 4: 0, 5: 4, 6: 7, 7: 5, 8: 2, 9: 12, 10: 10, 11: 1, 12: 8}, 14: {0: 7, 1: 4, 2: 11, 3: 10, 4: 9, 5: 5, 6: 0, 7: 1, 8: 12, 9: 3, 10: 8, 11: 2, 12: 13, 13: 6}, 15: {0: 7, 1: 8, 2: 1, 3: 5, 4: 10, 5: 12, 6: 6, 7: 9, 8: 4, 9: 0, 10: 3, 11: 14, 12: 13, 13: 11, 14: 2}, 16: {1: 0, 5: 1, 4: 2, 12: 3, 15: 4, 14: 5, 9: 6, 2: 7, 0: 8, 11: 9, 10: 10, 13: 11, 6: 12, 7: 13, 8: 14, 3: 15}}
        if not is_shuffle:
            for d in shuffle_map:
                shuffle_map[d] = {v: k for k, v in shuffle_map[d].items()}
        if len(b) == 1:
            res += b
        else:
            res += bytes(b[shuffle_map[len(b)][index]] for index in range(len(b)))
    return res

def check_chunks(input_bytes, chunk_size):
    zeros = 0
    not_zeros = 0
    for i in range(0, len(input_bytes), chunk_size):
        chunk = input_bytes[i:i+chunk_size]
        if all(b == 255 for b in chunk):
            zeros += 1
        else:
            not_zeros += 1
    return {"empty_chunk": zeros, "not_empty_chunk": not_zeros}

def xor(n, m):
    num_0 = int(n, 16)
    num_1 = int(m, 16)
    result = num_0 ^ num_1
    return hex(result)[2:]

def xor_bytes(byte1, byte2):
    result = bytes(x ^ y for x, y in zip(byte1, byte2))
    return result

def bin_list_to_hex(bin_list):
    bin_str = ''.join(str(bit) for bit in bin_list)
    hex_1 = hex(int(bin_str[:4], 2))
    hex_2 = hex(int(bin_str[4:], 2))
    return hex_1, hex_2

def bytes_to_image(image_bytes, width, height):
    pixel_bytes = list(image_bytes)
    reconstructed_image = Image.new('RGB', (width, height))
    for y in range(height):
        for x in range(width):
            start = (y * width + x) * 3
            pixel = struct.unpack('BBB', bytes(pixel_bytes[start:start + 3]))
            reconstructed_image.putpixel((x, y), pixel)
    return reconstructed_image

def image_to_bytes(image):
    width, height = image.size
    pixel_bytes = []
    for y in range(height):
        for x in range(width):
            pixel = image.getpixel((x, y))
            pixel_bytes.extend(struct.pack('BBB', *pixel))
    image_bytes = bytes(pixel_bytes)
    return image_bytes

class LFSR:
    def __init__(self, taps, initial_state):
        self.taps = taps
        self.state = initial_state

    
    def shift(self):
        feedback = sum(self.state[tap] for tap in self.taps) % 2
        new_bit = feedback
        self.state = self.state[1:] + [new_bit]
        return self.state

class ImageEncryption:
    def __init__(self, iv_list=None, tap_list=None, iv=None, rounds=3, chunk_size=16):
        assert 16 <= chunk_size < 25
        self.rounds = rounds
        self.chunk_size = chunk_size
        if iv_list is None:
            self.iv_list = []
            for _ in range(self.rounds + 1):
                self.iv_list.append([random.randint(0, 1) for _ in range(8)])
        else:
            self.iv_list = iv_list
        if tap_list is None:
            while True:
                taps = random.sample([i for i in range(8)], random.randint(3, 8))
                is_valid = True
                for l in self.iv_list:
                    if all(l[i] == 0 for i in range(min(taps), len(taps))):
                        is_valid = False
                if is_valid:
                    break
            self.tap_list = [taps] * (self.rounds + 1)
        else:
            self.tap_list = tap_list
            assert len(self.tap_list) == self.rounds + 1
            while True:
                is_valid = True
                for i in range(len(self.tap_list)):
                    taps = self.tap_list[i]
                    assert 3 <= len(taps) < 9
                    if all(self.iv_list[i][j] == 0 for j in range(min(taps), len(taps))):
                        is_valid = False
                        self.iv_list = []
                        for _ in range(self.rounds + 1):
                            self.iv_list.append([random.randint(0, 1) for _ in range(8)])
                if is_valid:
                  break
        if iv is None:
            self.iv = os.urandom(chunk_size)
        else:
            assert len(iv) == self.chunk_size
            self.iv = iv

        self.lfsr_list = []
        for i in range(self.rounds + 1):
            self.lfsr_list.append(LFSR(self.tap_list[i], self.iv_list[i]))

    def reset_state(self):
        self.lfsr_list = []
        for i in range(self.rounds + 1):
            self.lfsr_list.append(LFSR(self.tap_list[i], self.iv_list[i]))

    def stream_encryption(self, m_raw):
        c_raw = b""
        aa = 0
        for m in m_raw:
            m_hex = m.to_bytes(1, 'big').hex()
            m_1 = m_hex[0]
            m_2 = m_hex[1]
            for i in range(self.rounds):
                t = self.lfsr_list[i].shift()
                aa += 1
                k_1, k_2 = bin_list_to_hex(t)
                m_1 = s_substitute(xor(m_1, k_1))
                m_2 = s_substitute(xor(m_2, k_2))
            t = self.lfsr_list[-1].shift()
            k_1, k_2 = bin_list_to_hex(t)
            c_raw += bytes.fromhex(xor(m_1, k_1) + xor(m_2, k_2))

        return c_raw

    def stream_decryption(self, c_raw):
        m_raw = b""
        for c in c_raw:
            c_hex = c.to_bytes(1, 'big').hex()
            c_1 = c_hex[0]
            c_2 = c_hex[1]
            for i in range(self.rounds):
                k_1, k_2 = bin_list_to_hex(self.lfsr_list[-1-i].shift())
                c_1 = r_substitute(xor(c_1, k_1))
                c_2 = r_substitute(xor(c_2, k_2))
            k_1, k_2 = bin_list_to_hex(self.lfsr_list[0].shift())
            m_raw += bytes.fromhex(xor(c_1, k_1) + xor(c_2, k_2))

        return m_raw
    
    def encryption(self, m_raw):
        c_raw = b""
        k = self.iv
        for i in range(0, len(m_raw), self.chunk_size):
            m = m_raw[i:i+self.chunk_size]
            k = self.stream_encryption(xor_bytes(m, k))
            c_raw += k

        return c_raw

    def decryption(self, c_raw):
        m_raw = b""
        k = self.iv
        for i in range(0, len(c_raw), self.chunk_size):
            c = c_raw[i:i+self.chunk_size]
            m_raw += xor_bytes(self.stream_decryption(c), k)
            k = c

        return m_raw

if __name__ == '__main__':
    pass
