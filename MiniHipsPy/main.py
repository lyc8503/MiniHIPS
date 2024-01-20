import ctypes
from ctypes import *

import psutil

all_processes = psutil.process_iter()

helper = ctypes.CDLL("../x64/Debug/MiniHipsHelper.dll")
print(helper)

InjectDll = helper.InjectDllPid
InjectDll.argtypes = [c_ulong, c_char_p]
InjectDll.restype = c_int


for process in all_processes:
    process_info = process.as_dict(attrs=['pid', 'name', 'username'])

    if process_info['name'] != 'explorer.exe' and process_info['name'] != 'Notepad.exe':
        continue
    print(process_info)
    result = InjectDll(process_info['pid'], b"C:\\Users\\lyc\\Desktop\\MiniHIPS\\x64\\Debug\\MiniHipsApiDetours.dll")
    print(result)

