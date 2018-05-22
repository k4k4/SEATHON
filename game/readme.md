
Đề cho ta file `game` ARM</br>
![image](https://user-images.githubusercontent.com/23306492/40349150-e20996ac-5dcf-11e8-8cd8-4fe8c7421f02.png)</br>
Ta sử dụng **qemu** và **gdb-multiarch**,[peda-arm](https://github.com/alset0326/peda-arm) để debug, ta phải setup theo https://tradahacking.vn/debug-linux-kernel-v%E1%BB%9Bi-qemu-v%C3%A0-gdb-38c2cd29f616 và write up arm_exploit AceBear CTF https://github.com/phieulang1993/ctf-writeups/tree/master/2018/AceBearSecurityContest/pwn/arm_exploit</br>
Chương trình nhìn rối vl nhưng may cũng tìm dc cái lỗi `format string` chỗ hàm ` printf((const char *)&name);` nhưng chỉ khi ta win thì ta mới có thể vào exploit được</br>
![image](https://user-images.githubusercontent.com/23306492/40349372-a6410cbc-5dd0-11e8-8d1f-728aeda3e2c2.png)</br>
![image](https://user-images.githubusercontent.com/23306492/40349568-2fe34f70-5dd1-11e8-9f80-937d426081be.png)</br>
Rồi tiếp theo ta cần thắng đc boss thì ta có thể exploit dc</br>
Hàm main()</br>
![image](https://user-images.githubusercontent.com/23306492/40349731-ad7616de-5dd1-11e8-8f85-01d1263388de.png)</br>
Với `srand(time(0))` nếu cùng seed thì nó sẽ ra 1 chuỗi các số giống nhau vì time(0) ở server và time(0) ở máy client nếu chạy cùng trong 1 giây thì sẽ cho ra giá trị như nhau lúc đó ta có thể tính được các giá trị rand(). [link](https://github.com/phieulang1993/ctf-writeups/blob/master/2018/N1CTF/pwn/beeper/beeper.py)</br>
```
proc = CDLL("libc.so.6")
proc.srand(proc.time(0))
log.info('seed: %#x' % proc.time(0))
proc.rand()
```
Hàm `Attack()`</br>
```
int ATTACK()
{
  signed __int64 v0; // r3 OVERLAPPED
  signed __int64 v1; // ST00_8
  __int64 v2; // r1
  __int64 v3; // r1
  signed __int64 v5; // [sp+8h] [bp+8h]
  signed __int64 v6; // [sp+10h] [bp+10h]

  puts("YOU attack, BOSS defense!");
  printf("Attack:\n 1. Left\n 2. Center\n 3. Right?\n>> ");
  LODWORD(v0) = READ_INT(3) - 1;
  HIDWORD(v0) = (signed int)v0 >> 31;
  v1 = v0;
  printf("Bet:\n1. No Bet\n2. X2\n3. X3\n4. X4\n5. X5\n6. X6\n7. X7\n8. X8\n9. X9\n>> ");
  LODWORD(v0) = READ_INT(9);
  HIDWORD(v0) = (signed int)v0 >> 31;
  v5 = v0;
  LODWORD(v0) = rand();
  HIDWORD(v0) = (signed int)v0 >> 31;
  v6 = v0;
  sub_10C6C(v0, (signed int)v0 >> 31, 3, 0);
  if ( *(signed __int64 *)((char *)&v0 - 4) == v1 )
  {
    puts("Good Attack!");
    LODWORD(v2) = BOSSHP - v6 * v5;
    HIDWORD(v2) = (unsigned __int64)(*(_QWORD *)&BOSSHP - v5 * v6) >> 32;
    *(_QWORD *)&BOSSHP = v2;
  }
  else
  {
    puts("Bad Attack!");
    if ( v5 >= 2 )
    {
      puts("You lose bet!");
      LODWORD(v3) = HP - v6 * v5;
      HIDWORD(v3) = (unsigned __int64)(*(_QWORD *)&HP - v5 * v6) >> 32;
      *(_QWORD *)&HP = v3;
    }
  }
  return CHECK();
}
```
Hàm `Defense()`</br>
```
int DEFENSE()
{
  __int64 v0; // r3 OVERLAPPED
  __int64 v1; // ST00_8
  __int64 v2; // r1
  __int64 v3; // r1
  __int64 v5; // [sp+8h] [bp+8h]

  puts("BOSS attack, YOU defense!");
  printf("Defense:\n1. Left\n2. Center\n3. Right?\n>> ");
  LODWORD(v0) = READ_INT(3) - 1;
  HIDWORD(v0) = (signed int)v0 >> 31;
  v1 = v0;
  LODWORD(v0) = rand();
  HIDWORD(v0) = (signed int)v0 >> 31;
  v5 = v0;
  sub_10C6C(v0, (signed int)v0 >> 31, 3, 0);
  if ( *(__int64 *)((char *)&v0 - 4) == v1 )
  {
    HIDWORD(v3) = (unsigned __int64)(*(_QWORD *)&MANA[7] + v5) >> 32;
    LODWORD(v3) = *(_DWORD *)&MANA[7] + v5;
    *(_QWORD *)&MANA[7] = v3;
    puts("Good Defense!");
  }
  else
  {
    puts("Bad Defense!");
    LODWORD(v2) = HP - v5;
    HIDWORD(v2) = (unsigned __int64)(*(_QWORD *)&HP - v5) >> 32;
    *(_QWORD *)&HP = v2;
  }
  return CHECK();
}
```
Hàm `SKILL()` </br>
```
/ local variable allocation has failed, the output may be wrong!
int SKILL()
{
  int v0; // r3 OVERLAPPED
  int v1; // r4 OVERLAPPED
  bool v2; // zf
  __int64 v4; // r1
  __int64 v5; // [sp+0h] [bp+0h]

  printf("User Skill:\n 1. No\n 2. Kick\n 3. Punch\n 4. Doge\n 5. Rape?\n>> ");
  v0 = READ_INT(5);
  v1 = v0 >> 31;
  v5 = *(_QWORD *)&v0;
  v2 = v0 >> 31 == 0;
  if ( v0 >= 0 )
    v2 = v0 == 1;
  if ( v2 )
    return puts("OKAY!");
  if ( -195936478LL * *(_QWORD *)&v0 + *(_QWORD *)&MANA[7] < 1 )
    return printf("Not enough mana!");
  puts("Skill Attacked!");
  HIDWORD(v4) = (unsigned __int64)(*(_QWORD *)&BOSSHP - 195936478 * v5) >> 32;
  LODWORD(v4) = BOSSHP - 195936478 * v5;
  *(_QWORD *)&BOSSHP = v4;
  HIDWORD(v4) = (unsigned __int64)(*(_QWORD *)&MANA[7] - 195936478 * v5) >> 32;
  LODWORD(v4) = *(_DWORD *)&MANA[7] - 195936478 * v5;
  *(_QWORD *)&MANA[7] = v4;
  return CHECK();
}
```
Mấy cái hàm này dài vl nhưng để thắng dc thì cũng dễ vl attack win `rand()%3==input-1`</br>
để sử dụng `skill` khi `dword_106F0 >= *(_QWORD *)&MANA`
để exploit thì ta chỉ cần format string cho `exit_got thành  main(0x10855)` leak địa chỉ stack </br>
sau đó ta format string  `exit_got thành shell_address`</br>
[payload](https://github.com/k4k4/SEATHON/blob/master/game/game.py)</br>
![game](https://user-images.githubusercontent.com/23306492/40351124-dd0807d2-5dd5-11e8-97e7-a2ee5e201550.png)</br>
Xong, tới phần tìm kiếm người chơi cùng.</br>
Hiện tại trên pwnable.tw thì mình cũng giải quyết dc một số bài kha khá muốn kiếm người chơi cùng để trao đổi,học hỏi, cố gắng giải quyết thêm càng nhiều câu càng tốt</br>
![image](https://user-images.githubusercontent.com/23306492/40376242-14e47338-5e18-11e8-9fd1-f83e4d6aa538.png)

