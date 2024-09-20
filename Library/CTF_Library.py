from pwn import *
from sage.all import *
proof.all(False)
from Crypto.Util.number import *
from Crypto.Cipher import AES

import os

# Import everything under this folder
folder_path = os.path.dirname(os.path.realpath(__file__))
loaded_modules = set()
for dirpath, _, filenames in os.walk(folder_path):
	if "__pycache__" in dirpath:
		continue
	for filename in filenames:
		if not filename.endswith(".py") or filename == "CTF_Library.py":
			continue
		module_name = filename[:-3]
		if module_name in loaded_modules:
			continue
		module_path = os.path.join(dirpath, filename)
		import importlib.util
		spec = importlib.util.spec_from_file_location(module_name, module_path)
		module = importlib.util.module_from_spec(spec)
		try:
			spec.loader.exec_module(module)
		except Exception as e:
			print(f"Error importing {module_name}: {e}")
			continue
		globals().update(vars(module))
		loaded_modules.add(module_name)
