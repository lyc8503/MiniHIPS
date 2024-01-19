import ctypes
from ctypes import *

helper = ctypes.CDLL("../x64/Debug/MiniHipsHelper.dll")
print(helper)

InjectDll = helper.InjectDllPid
InjectDll.argtypes = [c_ulong, c_char_p]
InjectDll.restype = c_int

result = InjectDll(7236, b"C:\\Users\\lyc\\Desktop\\MiniHIPS\\x64\\Debug\\MiniHipsApiDetours.dll")
print("Result: ", result)
