# Import everything under this folder
import os
import sys
folder_path = os.path.dirname(os.path.realpath(__file__))
loaded_modules = set()
for dirpath, _, _ in os.walk(folder_path):
	if not "__pycache__" in dirpath and dirpath not in sys.path:
		sys.path.append(dirpath)
for dirpath, directory_names, filenames in os.walk(folder_path):
	if "__pycache__" in dirpath:
		continue
	for filename in filenames:
		if not filename.endswith(".py") or filename == "CTF_Library.py":
			continue
		module_name = filename[:-3]
		if module_name in loaded_modules:
			continue
		module_path = os.path.join(dirpath, filename)
		subdirectory = os.path.dirname(module_path)
		if subdirectory not in sys.path:
			sys.path.append(subdirectory)
		import importlib.util
		spec = importlib.util.spec_from_file_location(module_name, module_path)
		module = importlib.util.module_from_spec(spec)
		try:
			spec.loader.exec_module(module)
		except Exception as e:
			print(f"[INFO] <CTF_Library> Error importing {module_name}: {e}")
			assert False
		globals().update(vars(module))
		loaded_modules.add(module_name)

from sage.all import *
from sage.rings.factorint import factor_trial_division
proof.all(False)
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, ceil_div, size, isPrime, getPrime, getStrongPrime, getRandomInteger, getRandomNBitInteger, getRandomRange
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import hashlib
from pwn import *
from base64 import b64encode, b64decode

from multiprocessing import Pool
from concurrent.futures import ThreadPoolExecutor, as_completed
from gmpy2 import isqrt, iroot
from ast import literal_eval
from copy import deepcopy
from fractions import Fraction
import string
import numpy
import itertools
import random
import requests
import re
import traceback
import os
import json
import zlib
import subprocess
import time

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from collections import defaultdict

flag_char_set = "_{}:" + string.ascii_letters + string.digits + string.punctuation