#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
 ______  __    _ _______ ______   _______ _______ _______ ___     _______
|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |
|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___
| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___
|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|


Generate, resolve, and compare domain variations to detect typosquatting,
phishing, and brand impersonation

Copyright 2023 SecurityShrimp

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''


__version__ = '1.5.4'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'

import os
import sys
import ast
from datetime import datetime
import configParser


import smtplib
import mimetypes
from email.mime.multipart import MIMEMultipart
from email import encoders
from email.message import Message
from email.mime.base import MIMEBase
from email.mime.text import MIMEText


pwd = os.getcwd()

#load configuration file
parser = configparser.ConfigParser()
config = pwd + '/etc/MailConfig.conf'
parser.read( config ) #change this to speedtest.conf once configured


mail_host = parser['connection_info']['smtp_host']
mail_port = parser['connection_info']['smtp_port']
send_user = parser['credentials']['user']
send_pass = parser['credentials']['pword']
mail_recipients = parser['recipients']['sendToRecipients']


class sendmail:
	def __init__(self,subject,recipients):
		self.subject = subject
		self.recipients = recipients
		self.htmlbody = ''
		self.sender = sendUser
		self.senderpass = sendPass
		self.attachments = []

	def send(self):
		msg = MIMEMultipart('alternative')
		msg['From']=self.sender
		msg['Subject']=self.subject
		msg['To'] = ", ".join(self.recipients) # to must be array of the form ['mailsender135@gmail.com']
		msg.preamble = "Here is the output for the most recent run of DNSRazzle"
		#check if there are attachments if yes, add them
		if self.attachments:
			self.attach(msg)
		#add html body after attachments
		msg.attach(MIMEText(self.htmlbody, 'html'))
		#send
		s = smtplib.SMTP(mail_host + ':' + mail_port)
		s.starttls()
		s.login(self.sender,self.senderpass)
		s.sendmail(self.sender, self.recipients, msg.as_string())
		#test
    if debug == True:
      print(msg)
		s.quit()

	def htmladd(self, html):
		self.htmlbody = self.htmlbody+'<p></p>'+html

	def attach(self,msg):
		for f in self.attachments:

			ctype, encoding = mimetypes.guess_type(f)
			if ctype is None or encoding is not None:
				ctype = "application/octet-stream"

			maintype, subtype = ctype.split("/", 1)
      
			if maintype == "text":
				fp = open(f)
				# Note: we should handle calculating the charset
				attachment = MIMEText(fp.read(), _subtype=subtype)
				fp.close()
			else:
				fp = open(f, "rb")
				attachment = MIMEBase(maintype, subtype)
				attachment.set_payload(fp.read())
				fp.close()
				encoders.encode_base64(attachment)
			attachment.add_header("Content-Disposition", "attachment", filename=f)
			attachment.add_header('Content-ID', '<{}>'.format(f))
			msg.attach(attachment)

	def addattach(self, files):
		self.attachments = self.attachments + files




def sendemail(out_dir,mail_recipients):
	# subject and recipients
	mymail = sendmail('DNSRazzle output for ' +datetime.now().strftime('%m/%d/%Y'),mail_recipients)
	#start html body. Here we add a greeting.
	mymail.htmladd('Good morning, find the daily summary below.')
	#attach a file
	mymail.addattach(out_dir/results.zip)
	#send!
	mymail.send()
