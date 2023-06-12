#!/usr/bin/env python3
#----------------------------------------------------------------------------
# shaminator.py 
# Created By: Logan Patterson
# Created Date: 04/02/2023
# Version 1.0
# ---------------------------------------------------------------------------
""" Script that will search a specified directory recursively, check all detected .crt files
and if it's expired, it will store that and it's associated key file (if in same directory) in 
a variable. 

Then, it goes through and uses openssl and generates new certificates and key files for each expired
cert, maintaing the same name and subject. 

This was built to fix the expired certificate issue with Security Onion 2.3.110. 

Updates the validity_days variable to increase the time on the newly made certificates and update
the /etc/pki path after os.walk to change where you want the script to search. 
"""
# ---------------------------------------------------------------------------

import os
import subprocess
import datetime

# Sets how long the certificate will last after it's been remade (in days)
# Change this to change the expiration time.
validity_days = 365
# Begin looping through the specified directory
# Update to /opt/so/conf/filebeat/etc/pki to fix filebeat cert in newer deployments
# I haven't tested it by targetting and crawling / 
for root, dirs, files in os.walk('/etc/pki'):
    for file in files:
        # If the file is a .crt file, store it in cert_file and get ready to check to see 
        # if there is an associated key file by added the .crt file name to a name.key variable
        if file.endswith('.crt'):
            cert_file = os.path.join(root, file)
            key_file = os.path.join(root, file.replace('.crt', '.key'))
            # If there is an associated key file then we grab the current date time and the datetime of the certifcate files
            if os.path.isfile(key_file):
                cert_date = subprocess.check_output(['openssl', 'x509', '-in', cert_file, '-noout', '-enddate']).decode('utf-8').strip().split('=')[1]
                cert_date_obj = datetime.datetime.strptime(cert_date, '%b %d %H:%M:%S %Y %Z')
                now = datetime.datetime.now()
                days_left = (cert_date_obj - now).days
                # If the certificate is expired, then we update it by creating a new one with the same name and subject
                # We also recreate an associated key file to go with the cert file
                if days_left <= 0:
                    print("Certificate is expired, updating: {}".format(cert_file))
                    subject = subprocess.check_output(['openssl', 'x509', '-in', cert_file, '-noout', '-subject']).decode('utf-8').strip().split('=')[1]
                    subj_str = '/CN={}'.format(subject)
                    if ',' in subject:
                        for elem in subject.split(','):
                            if '=' in elem:
                                key, value = elem.split('=')
                                if key and value:
                                    subj_str += '/{},{}'.format(key, value)
                    subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-keyout', key_file, '-out', cert_file, '-days', str(validity_days), '-subj', subj_str])
                    print("Updated certificate: {}".format(cert_file))
                else:
                    print("Certificate is valid for {} more days, skipping: {}".format(days_left, cert_file))
