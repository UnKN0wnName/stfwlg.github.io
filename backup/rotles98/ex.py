from pwn import *
context.log_level = "debug"

HOST = "localhost"
#HOST = ""
PORT = 4444
#PORT = 

s = remote(HOST, PORT)

elf = ELF("./")
#libc = ELF("./")
pause()

s.interactive()
