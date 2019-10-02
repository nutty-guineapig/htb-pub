#!/usr/bin/python

#in vi :cm=blowfish
#:X
#W
#We see that there's a file thats encrypted with VimCrypt~02 (blowfish) 
#VIM incorrectly implemented blowfish for i think the first 64 bytes (8 blocks), making it possible to recover plaintext if 
#the first block of plaintext is known 

#We also have a file named creds.old that contains
#rijndael / Password1
#this has enough to go on, since we know the user name is rijndael (a block of data)

#Lets do the following:
#create two files
#hellothere how are you doing?
#password testing

#take creds old contents
#password Trymenowyo!

#read the file
#strip out the header: VimCrypt~02
#strip out the iv : 8 bytes
#strip out the salt : 8 bytes
#take first block of ciphertext
#xor it with the first block of known plaintext
#this should give us the key

#take the second block .. to eight block
#xor it with the keystream
#we should be able to uncover the plaintext

import sys
import struct
from binascii import b2a_hex, a2b_hex
from Crypto.Hash import SHA256

def letsGoSon(data, plaintext):
	salt = data[0:8]
	iv = data[8:16]
	restOfData=data[16:]

	#restOfData= b2a_hex(restOfData1[:16])
	
	blocksize = 8 
	print (restOfData)
	print ("total length %d" % len(restOfData))
	#
	firstBlock=restOfData[0:8]
	secondBlock = restOfData[8:16]

	f = bytearray(firstBlock)
	p = bytearray(plaintext)

	print (len(f))
	print (len(p))
	output = bytearray(len(f))
	
	for i in range (len(f)):
		output[i] = f[i] ^ p[i]

	print (output)

	c2 = bytearray(secondBlock)
	real = bytearray(len(c2))
	for i in range (len(c2)):
		real[i] = c2[i] ^ output[i]
		
	dataByte = bytearray(restOfData)
	plain= bytearray()

	#proof of concept worked, lets go for the gold nike
	for o in range(len(dataByte)):
		plain.append( dataByte[o] ^ output[o%8])
	
	print (plain)

def main():
	import argparse
	parser = argparse.ArgumentParser(description='pigscript')
	parser.add_argument('--file', '-f', type=str, help='filename to try')
	parser.add_argument('--plaintext', '-p', type=str, help='first block of plaintext')
	args = parser.parse_args()

	print ("filename is %s"% args.file)
	print ("plaintext is %s"% args.plaintext)

	with open(args.file, "rb") as fh:
		data = fh.read()
		if data[0:12] == b"VimCrypt~02!":
			print ("we in business son, its a vimcrypt~02 file!")
			letsGoSon(data[12:],args.plaintext)

if __name__ == '__main__':
	sys.exit(main())
