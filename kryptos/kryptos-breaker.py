#!/usr/bin/python3
import random
import sys 
import json
import hashlib
import binascii
import requests as req
from ecdsa import VerifyingKey, SigningKey, NIST384p
import argparse

#run kryptos.py to start the server
# based on seeing how kryptos.py works
# Our objectives
# Discover seed due to weak PRNG 
	#generate a sample size of n secure_rng values
	
#generate key 
#sign request
#look for positive response

def secure_rng(seed): 
    # Taken from the internet - probably secure
    p = 2147483647
    g = 2255412

    keyLength = 32
    ret = 0
    ths = round((p-1)/2)
    for i in range(keyLength*8):
        seed = pow(g,seed,p)
        if seed > ths:
            ret += 2**i
    return ret


url = 'http://127.0.0.1:81/'
def findSeed():

	# basic message that will eval on the service
	msg = '2+2'
	
	#open our list of seeds and sign our own message
	#one of these should be accepted by the server, since the rng is borked
	with open("allseeds.txt","r") as f:
		for number in f.readlines():
			print ("trying number %s" % number)
			currentSeed= int(number.strip(),10)
			sk = SigningKey.from_secret_exponent(currentSeed+1, curve=NIST384p)
			signature = binascii.hexlify(sk.sign(str.encode(msg)))
			r=req.post(url+"eval", json={"expr":"2+2", "sig":signature.decode()})
			if (r.text != "Bad signature"):
				print ("seed found" + str(currentSeed+1))
				with open("s.txt","w") as f:	
					f.write("%d\n" % x)
				break

def genSeedList():
	p = 2147483647
	g = 2255412
	elements={1}
	for i in range (100000):
		x = pow(g,i,p)
		elements.add(x)
	
	print ("there are %d unique elements in the set" % len(elements))
	values={0}
	
	#lets gen potential seeds based on the unique values 
	for x in elements:
	        values.add( secure_rng(x) )

	print ("There are %d different values in this set." % len(values))
	
	#write these to a file
	with open("allseeds.txt","w") as f:
	    for x in values:
        	f.write("%d\n" % x)

#make request to server with our own msg, since now know the seed
def letTheDogsOut(msg):
	with open("s.txt","r") as f:
		for number in f.readlines():
			currentSeed= int(number.strip(),10)
	sk = SigningKey.from_secret_exponent(currentSeed, curve=NIST384p)
	signature = binascii.hexlify(sk.sign(str.encode(msg)))
	r=req.post(url+"eval", json={"expr":msg, "sig":signature.decode()})
	print (r.text)

def main():
	parser = argparse.ArgumentParser(description='pigClient')
	parser.add_argument('--option', '-o',  help='GENFILE/SEED/GO')
	parser.add_argument('-go', '-g', help='let dogs are out!')
	args = parser.parse_args()
	option = args.option

	if (option == "SEED"):
		findSeed()

	#go takes in the msg we want to send		
	elif (option == "GO"):
		letTheDogsOut(args.go)

	elif (option == "GENFILE"):
		genSeedList()
	
	else:
		print("invalid option")

if __name__ == '__main__':
	sys.exit(main())