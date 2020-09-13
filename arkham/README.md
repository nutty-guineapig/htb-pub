scrap notes  
* After connecting over SMB, we find a backup file containing configuration files for the server (encryption key and hmac key)
* turns out they are using myserver.faces. The VIEWSTATE is vulnerable to deserialization attacks

our objective here is to:
1. retrieve viewstate, and attempt to decrypt it... if this works, then there is a lil bit of progress
2. re-encrypt the viewstate manually in our script, and send it to the server... if the server accepts this, then we are close to ready
3. generate a ysoserial serialized payload, encrypt then mac (this was discovered by reading through the implementation of myfaces-core-assembly-1.2.12-src)

a quick test is to generate a yso serial payload such as cmd.exe /c ping -n 2 <ourip> and use tcpdump (sudo tcpdump -i tun0 icmp and icmp[icmptype]=icmp-echo)  
to see if the server pings us back... if so then we can curl nc.exe and then have the serve give us a reverse shell

