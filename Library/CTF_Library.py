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
proof.all(False)
from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad
from pwn import *

from multiprocessing import Pool
import itertools
import random
import traceback
import os
import json
import re
import ast