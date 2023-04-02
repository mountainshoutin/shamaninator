# shamaninator

Script that will search a specified directory recursively, check all detected .crt files
and if it's expired, it will store that and it's associated key file (if in same directory) in 
a variable. 

Then, it goes through and uses openssl and generates new certificates and key files for each expired
cert, maintaing the same name and subject. 

This was built to fix the expired certificate issue with Security Onion 2.3.110. 

Updates the validity_days variable to increase the time on the newly made certificates and update
the /etc/pki path after os.walk to change where you want the script to search. 
