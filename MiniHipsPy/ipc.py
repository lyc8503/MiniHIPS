from ctypes import *
import ctypes.util

helper = CDLL("x64/Debug/MiniHipsHelper.dll")
print(helper)


IPCQueueWaitMsg = helper.IPCQueueWaitMsg
IPCQueueWaitMsg.argtypes = []
IPCQueueWaitMsg.restype = c_wchar_p

def read_msg():
    # TODO: free memory
    res = IPCQueueWaitMsg()
    return res

while True:
    print(read_msg())