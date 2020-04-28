#!/usr/bin/python3
from web3 import Web3
import os, subprocess, time, json
import hashlib

address = "0x927B154Ca52BA09b7EA873f31dDCE3b872bED61A"

with open('ChainsawClub.json') as f:
        contractData = json.load(f)

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:63991'))
w3.eth.defaultAccount = w3.eth.accounts[0]

#contract = w3.eth.contract(abi=contractData['abi'],bytecode=contractData['bytecode'],address=address)
contract = w3.eth.contract(abi=contractData['abi'],address=address)
print (w3.eth.defaultAccount)
contract.functions.reset().call()
print (contract.functions.getUsername().call())
print (contract.functions.getPassword().call())
print (contract.functions.setUsername('test').transact({'from': w3.eth.defaultAccount}))
password = 'testers'
p = hashlib.md5()
p.update(password.encode('utf-8'))
print (contract.functions.setPassword(p.hexdigest()).transact({'from':w3.eth.defaultAccount}))
contract.functions.setApprove(True).transact({'from': w3.eth.defaultAccount})
contract.functions.transfer(1000).transact({'from': w3.eth.defaultAccount})
print (contract.functions.getSupply().call())
#print (contract.functions.reset().call())
