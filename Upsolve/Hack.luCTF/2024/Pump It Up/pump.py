import secrets
from Crypto.Cipher import AES # pip install pycryptodome
import os
import string
import audio_engine

# flag = flag{y0u_
with open("../SECRET/flag.txt", "r") as fp:
    flag = fp.read().strip()
flag = flag.encode().hex()

if not os.path.isdir("snippets"):
    os.mkdir("snippets")

    for cnt,s in enumerate(string.digits + "abcdef"):
        os.system(f"ffmpeg -ss {cnt} -t 1 -i pump.opus snippets/{ord(s)}.voc")
sound_bites = []
for s in flag:
    out = audio_engine.extract_sound_data(f"snippets/{ord(s)}.voc")
    sound_bites.append(out)
audio_engine.create_voc_file("flag.voc", b"".join(sound_bites)) 


def encrypt_it():
    key = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    with open("flag.voc", "rb") as f:
        val = f.read()
    val += b"\x00" * (16 - len(val) % 16)
    with open("flag.enc", "wb") as f:
        f.write(cipher.encrypt(val))
encrypt_it()