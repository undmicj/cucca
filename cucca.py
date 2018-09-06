# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ElementTree
import requests
import yaml
import smtplib
import datetime
import ast
import os
import re
import xlsxwriter
import mimetypes
import logging
import glob
import base64
import ruamel.yaml
import getpass
from axltoolkit import AxlToolkit
from ldap3 import Server, Connection, SUBTREE
from email import encoders
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from Cryptodome.Cipher import AES

class Email:
    # This class handles the creation and sending of email messages via SMTP.  This class also handles attachments and
    # can send HTML messages.  The code comes from various places around the net and from my own brain.
    def __init__(self, smtpserver):
        # Create a new empty email message object.
        # @param smtpServer: The address of the SMTP server
        # @type smtpServer: String
        self._textBody = None
        self._htmlBody = None
        self._subject = ""
        self._authUser = VAR_MAIL_AUTH_USERNAME
        self._authPassword = VAR_MAIL_AUTH_PASSWORD
        self._smtpServer = smtpserver
        self._smtpPort = 587
        self._reEmail = re.compile(r"[^@]+@[^@]+")
        self._debug = False
        self.clearRecipients()
        self.clearAttachments()

    def send(self):
        # Validate and send the email message represented by this object.
        if self._textBody is None and self._htmlBody is None:
            raise Exception("Error! Must specify at least one body type (HTML or Text)")
        if len(self._to) == 0:
            raise Exception("Must specify at least one recipient")
        # Create the message part
        if self._textBody is not None and self._htmlBody is None:
            msg = MIMEText(self._textBody, "plain")
        elif self._textBody is None and self._htmlBody is not None:
            msg = MIMEText(self._htmlBody, "html")
        else:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(self._textBody, "plain"))
            msg.attach(MIMEText(self._htmlBody, "html"))
        # Add attachments, if any
        if len(self._attach) != 0:
            tmpmsg = msg
            msg = MIMEMultipart()
            msg.attach(tmpmsg)
        for fname, attachname in self._attach:
            if not os.path.exists(fname):
                print("File '{}' does not exist.  Not attaching to email.".format(fname))
                continue
            if not os.path.isfile(fname):
                print("Attachment '{}' is not a file.  Not attaching to email.".format(fname))
                continue
            # Guess at encoding type
            ctype, encoding = mimetypes.guess_type(fname)
            if ctype is None or encoding is not None:
                # No guess could be made so use a binary type.
                ctype = 'application/octet-stream'
            maintype, subtype = ctype.split('/', 1)
            if maintype == 'text':
                fp = open(fname)
                attach = MIMEText(fp.read(), _subtype=subtype)
                fp.close()
            elif maintype == 'image':
                fp = open(fname, 'rb')
                attach = MIMEImage(fp.read(), _subtype=subtype)
                fp.close()
            elif maintype == 'audio':
                fp = open(fname, 'rb')
                attach = MIMEAudio(fp.read(), _subtype=subtype)
                fp.close()
            else:
                fp = open(fname, 'rb')
                attach = MIMEBase(maintype, subtype)
                attach.set_payload(fp.read())
                fp.close()
                # Encode the payload using Base64
                encoders.encode_base64(attach)
            # Set the filename parameter
            if attachname is None:
                filename = os.path.basename(fname)
            else:
                filename = attachname
            attach.add_header('Content-Disposition', 'attachment', filename=filename)
            msg.attach(attach)
        # Some header stuff
        msg['Subject'] = self._subject
        msg['From'] = self._from
        msg['To'] = ", ".join(self._to)
        msg.preamble = "You need a MIME enabled mail reader to see this message"
        # Send message
        msg = msg.as_string()
        mailserver = smtplib.SMTP(self._smtpServer, self._smtpPort)
        if self._debug:
            mailserver.set_debuglevel(1)
        if self._authUser:
            mailserver.ehlo()
            mailserver.starttls()
            mailserver.ehlo()
            mailserver.login(self._authUser, self._authPassword)
        mailserver.sendmail(self._from, self._to, msg)
        mailserver.quit()

    def setDebug(self, debug):
        # Set the debug option.
        self._debug = debug

    def setSubject(self, subject):
        # Set the subject of the email message.
        self._subject = subject

    def setFrom(self, address):
        # Set the email sender.
        if not self.validateEmailAddress(address):
            raise Exception("Invalid email address '%s'" % address)
        self._from = address

    def clearRecipients(self):
        # Remove all currently defined recipients for the email message.
        self._to = []

    def addRecipient(self, address):
        # Add a new recipient to the email message.
        if not self.validateEmailAddress(address):
            raise Exception("Invalid email address '%s'" % address)
        self._to.append(address)

    def setTextBody(self, body):
        # Set the plain text body of the email message.
        self._textBody = body

    def setHtmlBody(self, body):
        # Set the HTML portion of the email message.
        self._htmlBody = body

    def clearAttachments(self):
        # Remove all file attachments.
        self._attach = []

    def addAttachment(self, fname, attachname=None):
        # Add a file attachment to this email message.
        # @param fname: The full path and file name of the file to attach.
        # @type fname: String
        # @param attachname: This will be the name of the file in the email message if set.  If not set then the
        # filename will be taken from the fname parameter above.
        # @type attachname: String
        if fname is None:
            return
        self._attach.append((fname, attachname))

    def validateEmailAddress(self, address):
        # Validate the specified email address.
        # @return: True if valid, False otherwise
        # @rtype: Boolean
        if self._reEmail.search(address) is None:
            return False
        return True


def ldaplookup():
    logger.info('Capturing Group Membership')
    server = Server(VAR_LDAP_SERVER, port=VAR_LDAP_PORT, use_ssl=VAR_LDAP_SSL, get_info=None)
    ldapbind = Connection(server, user=VAR_LDAP_USERNAME, password=VAR_LDAP_PASSWORD, auto_bind=True)
    ldapbind.search(search_base=VAR_LDAP_SEARCH_BASE, search_filter=VAR_LDAP_GROUP, attributes=VAR_LDAP_ATTRIBUTE,
                    search_scope=SUBTREE, size_limit=0)
    # Parsing LDAP Data
    logger.info('Parsing Group Membership')
    ldapresult = ast.literal_eval(ldapbind.response_to_json())
    ldapuser = []
    if ldapresult['entries'] is not None:
        for entry in ldapresult['entries']:  # user is a list of dictionaries, containing user info
            ldapuser.append(entry['attributes']['sAMAccountName'])
    ldapuserlist = [''.join(x) for x in ldapuser]  # This converts user(list of lists) to just a list of users
    return ldapuserlist


def udslookup(username):

    r = requests.get("https://" + VAR_UDS_FQDN + ":8443/cucm-uds/clusterUser?username=" + username, verify=False)
    logger.debug("UDS URL for {0} is https://{1}:8443/cucm-uds/clusterUser?username={0}".format(username, VAR_UDS_FQDN))
    # print(r.status_code)
    # print(r.headers)
    # print(r.content)

    root = ElementTree.fromstring(r.content)
    for child in root.iter('result'):
        if child.attrib['found'] == 'false':
            logger.debug("{0} not found in UDS!".format(username))
            userhomecluster = "Not Provisioned"
            return userhomecluster
    for item in root.iter('homeCluster'):
        userhomecluster = item.text
    return userhomecluster


# Initialize Config File and Read in Variables
with open("config.yml", "r") as ymlfile:
    config = yaml.load(ymlfile)

VAR_DEBUG = config["debug"]["level"]
VAR_LDAP_SERVER = config["ldap"]["server"]
VAR_LDAP_PORT = config["ldap"]["port"]
VAR_LDAP_SSL = config["ldap"]["ssl"]
VAR_LDAP_USERNAME = config["ldap"]["username"]
VAR_LDAP_PASSWORD = config["ldap"]["password"]
VAR_LDAP_SEARCH_BASE = config["ldap"]["searchbase"]
VAR_LDAP_GROUP = config["ldap"]["querygroup"]
VAR_LDAP_ATTRIBUTE = config["ldap"]["attribute"]
VAR_MAIL_SERVER = config["mail"]["server"]
VAR_MAIL_AUTH_REQ = config["mail"]["auth_required"]
VAR_MAIL_AUTH_USERNAME = config["mail"]["auth_username"]
VAR_MAIL_AUTH_PASSWORD = config["mail"]["auth_password"]
VAR_MAIL_SENDER = config["mail"]["sender"]
VAR_MAIL_RECIPIENT = config["mail"]["recipient"]
VAR_UDS_FQDN = config["cucm"]["primary_uds_server"]
VAR_AXL1_PASSWORD = config["cucm"]["cluster1"]["password"]
VAR_AXL2_PASSWORD = config["cucm"]["cluster2"]["password"]
VAR_AXL3_PASSWORD = config["cucm"]["cluster3"]["password"]
VAR_AXL4_PASSWORD = config["cucm"]["cluster4"]["password"]
VAR_CRED_VARIABLES = {
    "VAR_LDAP_PASSWORD": VAR_LDAP_PASSWORD,
    "VAR_MAIL_AUTH_PASSWORD": VAR_MAIL_AUTH_PASSWORD,
    "VAR_AXL1_PASSWORD": VAR_AXL1_PASSWORD,
    "VAR_AXL2_PASSWORD": VAR_AXL2_PASSWORD,
    "VAR_AXL3_PASSWORD": VAR_AXL3_PASSWORD,
    "VAR_AXL4_PASSWORD": VAR_AXL4_PASSWORD
}
# ENCRYPTION VARIABLES
PADDING = '#'
pad_it = lambda s: bytes(s+(16 - len(s)%16)*PADDING, encoding='utf8')
key = b'1234567812345678'
iv = b'1234567812345678'


# Initialize Logging
log_filename = 'cucca.log'
logger = logging.getLogger('cucca-logging')
logger.setLevel(VAR_DEBUG)
handler = logging.handlers.RotatingFileHandler(log_filename, maxBytes=2000000, backupCount=5)
formatter_debug = logging.Formatter('%(asctime)s [%(levelname)8s](%(funcName)s:%(lineno)d): %(message)s',
                                    datefmt='%Y-%m-%d %H:%M:%S')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logfiles = glob.glob('%s*' % log_filename)
logger.info('Starting CDW Unified Communications Compliance Auditor')


# --------- START ENCRYPTION --------- #
def encrypt_data(plaintext):
    source = plaintext
    generator = AES.new(key, AES.MODE_CBC, iv)
    crypt = generator.encrypt(pad_it(source))
    # print("The encrypted bytes are:")
    # print(crypt)
    # print()
    cryptedStr = base64.b64encode(crypt)
    # print("The Base64 bytes are")
    # print(type(cryptedStr))
    # print(cryptedStr)
    # print()
    return(cryptedStr)

# --------- START DECRYPTION --------- #
def decrypt_data(cryptedStr):
    #DECODE BASE64
    # print("Base64 is:", cryptedStr)
    # print(type(cryptedStr))
    # print()
    decryptStr = base64.b64decode(cryptedStr)
    # print("Decoded Base64 is:", decryptStr)
    # print(type(decryptStr))
    # print()

    #DECRYPT
    generator2 = AES.new(key, AES.MODE_CBC, iv)
    decrypt = generator2.decrypt(decryptStr)
    # print("Decrypted data is")
    # print(decrypt)
    # print(type(decrypt))
    # print()

    # DECODE AND REMOVE PADDING
    decryptedstring = decrypt.decode('ASCII')
    final = decryptedstring.rstrip(PADDING)
    # print("The Password is:", final)
    return final


# --------- READ CONFIG AND GATHER PASSWORDS IF NEEDED --------- #
with open("config.yml", 'r') as readconf:
    config = ruamel.yaml.load(readconf, ruamel.yaml.RoundTripLoader)

# CHECK FOR MISSING CREDS AND IF MISSING GATHER AND ENCRYPT
logger.info("Validating Credentials Present")
for entry in VAR_CRED_VARIABLES:
    password = VAR_CRED_VARIABLES[entry]
    if not password:
        ptpassword = getpass.getpass(prompt="Enter the password for the {0} Account:".format(entry))
        passwordencrypt = encrypt_data(ptpassword)
        if entry == "VAR_LDAP_PASSWORD":
            passwordencrypt = encrypt_data(ptpassword)
            config['ldap']['password'] = str(passwordencrypt)
            # print(type(passwordencrypt))
            # print("Encrypted password is", passwordencrypt)
        elif entry == "VAR_MAIL_AUTH_PASSWORD":
            passwordencrypt = encrypt_data(ptpassword)
            config["mail"]["auth_password"] = str(passwordencrypt)
            # print(type(passwordencrypt))
            # print("Encrypted password is", passwordencrypt)
        elif entry == "VAR_AXL1_PASSWORD":
            passwordencrypt = encrypt_data(ptpassword)
            config["cucm"]["cluster1"]["password"] = str(passwordencrypt)
            # print(type(passwordencrypt))
            # print("Encrypted password is", passwordencrypt)
        elif entry == "VAR_AXL2_PASSWORD":
            passwordencrypt = encrypt_data(ptpassword)
            config["cucm"]["cluster2"]["password"] = str(passwordencrypt)
            # print(type(passwordencrypt))
            # print("Encrypted password is", passwordencrypt)
        elif entry == "VAR_AXL3_PASSWORD":
            passwordencrypt = encrypt_data(ptpassword)
            config["cucm"]["cluster3"]["password"] = str(passwordencrypt)
            # print(type(passwordencrypt))
            # print("Encrypted password is", passwordencrypt)
        elif entry == "VAR_AXL4_PASSWORD":
            passwordencrypt = encrypt_data(ptpassword)
            config["cucm"]["cluster4"]["password"] = str(passwordencrypt)
            # print(type(passwordencrypt))
            # print("Encrypted password is", passwordencrypt)
# THIS ELSE SHOULD NOT BE NEEDED BUT IS GOOD FOR DEBUGGING
    else:
        # print("Encrypted password found in config file:", password)
        foundencpassword = ast.literal_eval(password)
        # print(type(foundencpassword))
        passworddecrypt = decrypt_data(foundencpassword)
        # print("The password in the config file is:", passworddecrypt)

# ONCE PASSWORD(S) ARE FOUND WRITE ENCRYPTED FORM TO CONFIG FILE
with open('config.yml', 'w') as updatedconfig:
    ruamel.yaml.dump(config, updatedconfig, ruamel.yaml.RoundTripDumper)


# READ CONFIG FILE AGAIN(THIS TIME WILL HAVE ALL CREDS POPULATED
with open("config.yml", 'r') as readconf2:  # IS THE 2 NEEDED HERE OR CAN WE USE READCONF2 AGAIN
    config = ruamel.yaml.load(readconf2, ruamel.yaml.RoundTripLoader)
# READ IN CRED VARIABLES AGAIN (THEY WILL BE ENCRYPTED)
VAR_LDAP_PASSWORD = config["ldap"]["password"]
VAR_MAIL_AUTH_PASSWORD = config["mail"]["auth_password"]
VAR_AXL1_PASSWORD = config["cucm"]["cluster1"]["password"]
VAR_AXL2_PASSWORD = config["cucm"]["cluster2"]["password"]
VAR_AXL3_PASSWORD = config["cucm"]["cluster3"]["password"]
VAR_AXL4_PASSWORD = config["cucm"]["cluster4"]["password"]
# MIGHT HAVE TO UPDATE CRED DICTIONARY AGAIN
VAR_CRED_VARIABLES = {
    "VAR_LDAP_PASSWORD": VAR_LDAP_PASSWORD,
    "VAR_MAIL_AUTH_PASSWORD": VAR_MAIL_AUTH_PASSWORD,
    "VAR_AXL1_PASSWORD": VAR_AXL1_PASSWORD,
    "VAR_AXL2_PASSWORD": VAR_AXL2_PASSWORD,
    "VAR_AXL3_PASSWORD": VAR_AXL3_PASSWORD,
    "VAR_AXL4_PASSWORD": VAR_AXL4_PASSWORD
}

# ITERATE CREDS AND DECRYPT
for entry in VAR_CRED_VARIABLES:
    password = VAR_CRED_VARIABLES[entry]
    print("Attempting to read credentials for {0}".format(entry))
    if not password:
        print("Error, missing credentials for {0}".format(entry))
        # WRITE ENCRYPTED PASSWORD TO CONFIG FILE <-- MOVED OUTSIDE OF FOR LOOP
    else:
        print("Encrypted password found in final config file:", password)
        foundencpassword = ast.literal_eval(password)
        # print(type(foundencpassword))
        passworddecrypt = decrypt_data(foundencpassword)
        print("The password in the final config file is:", passworddecrypt)
        VAR_CRED_VARIABLES[entry] = passworddecrypt

# UPDATE VARIABLES FROM DICTONARY FOR USE
VAR_LDAP_PASSWORD = VAR_CRED_VARIABLES["VAR_LDAP_PASSWORD"]
VAR_MAIL_AUTH_PASSWORD = VAR_CRED_VARIABLES["VAR_MAIL_AUTH_PASSWORD"]
VAR_AXL1_PASSWORD = VAR_CRED_VARIABLES["VAR_AXL1_PASSWORD"]
VAR_AXL2_PASSWORD = VAR_CRED_VARIABLES["VAR_AXL2_PASSWORD"]
VAR_AXL3_PASSWORD = VAR_CRED_VARIABLES["VAR_AXL3_PASSWORD"]
VAR_AXL4_PASSWORD = VAR_CRED_VARIABLES["VAR_AXL4_PASSWORD"]


# Create AXL Instances
axl1 = AxlToolkit(username=config["cucm"]["cluster1"]["username"], password=VAR_AXL1_PASSWORD,
                  server_ip=config["cucm"]["cluster1"]["server_ip"], tls_verify=False, version='12.0')
axl2 = AxlToolkit(username=config["cucm"]["cluster2"]["username"], password=VAR_AXL2_PASSWORD,
                  server_ip=config["cucm"]["cluster2"]["server_ip"], tls_verify=False, version='12.0')
axl3 = AxlToolkit(username=config["cucm"]["cluster3"]["username"], password=VAR_AXL3_PASSWORD,
                  server_ip=config["cucm"]["cluster3"]["server_ip"], tls_verify=False, version='12.0')
axl4 = AxlToolkit(username=config["cucm"]["cluster4"]["username"], password=VAR_AXL4_PASSWORD,
                  server_ip=config["cucm"]["cluster4"]["server_ip"], tls_verify=False, version='12.0')

# Execute LDAP Lookup, UDS Lookup, AXL Lookup
ldapuserlist = ldaplookup()
ldapusers = {}
for ldapuser in ldapuserlist:
    ldapusers[ldapuser] = {}
    ldapusers[ldapuser]['udsHomeCluster'] = udslookup(ldapuser)  # Query UDS for home cluster, store value in user dict
    # logging.DEBUG("UDS URL says Home Cluster is {0} for {1}").format(ldapusers[ldapuser]['udsHomeCluster'],[ldapuser])
    if ldapusers[ldapuser]['udsHomeCluster'] == config["cucm"]["cluster1"]["server_fqdn"]:
        result = axl1.list_users(userid=ldapuser)
    elif ldapusers[ldapuser]['udsHomeCluster'] == config["cucm"]["cluster2"]["server_fqdn"]:
        result = axl2.list_users(userid=ldapuser)
    elif ldapusers[ldapuser]['udsHomeCluster'] == config["cucm"]["cluster3"]["server_fqdn"]:
        result = axl3.list_users(userid=ldapuser)
    elif ldapusers[ldapuser]['udsHomeCluster'] == config["cucm"]["cluster4"]["server_fqdn"]:
        result = axl4.list_users(userid=ldapuser)
    else:
        logger.debug("No AXL details for homecluster: {0}".format(ldapusers[ldapuser]['udsHomeCluster']))
        result = axl1.list_users(userid=ldapuser)
    if result['return'] is not None:
        for user in result['return']['user']:  # user is a list of dictionaries, containing user info
            # ldapusers[user['userid']]['uuid'] = user['uuid']  # Adds uuid key
            ldapusers[user['userid']]['firstName'] = user['firstName']
            ldapusers[user['userid']]['lastName'] = user['lastName']
            ldapusers[user['userid']]['homeCluster'] = user['homeCluster']
            ldapusers[user['userid']]['imAndPresenceEnable'] = user['imAndPresenceEnable']
            if ldapusers[user['userid']]['imAndPresenceEnable'] == 'true':
                ldapusers[user['userid']]['complianceStatus'] = "Non-Compliant"
            else:
                ldapusers[user['userid']]['complianceStatus'] = "Compliant"
            if user['serviceProfile']['_value_1'] is not None:
                ldapusers[user['userid']]['serviceProfile'] = user['serviceProfile']
            elif user['serviceProfile']['_value_1'] is None:
                ldapusers[user['userid']]['serviceProfile'] = {'_value_1': "Use System Default"}
            if ldapusers[user['userid']]['udsHomeCluster'] == "Not Provisioned":
                ldapusers[user['userid']]['serviceProfile'] = {'_value_1': "N/A"}

# Log User Dictionaries and Capture Compliance Statistics
logger.info('Capturing Compliance Statistics')
noncompliant = []
compliant = []
for u_id, u_info in ldapusers.items():
    logger.debug("userid:{0}".format(u_id))
    for key in u_info:
        logger.debug("{0}:{1}".format(key, u_info[key]))
        if key == 'imAndPresenceEnable':
            if u_info[key] == 'true':
                noncompliant.append(u_id)
                logger.debug("{0} is enabled for IM&P".format(u_id))
            else:
                compliant.append(u_id)
                logger.debug("{0}is not enabled for IM&P".format(u_id))

# Compile HTML Email
logger.info('Compiling Email')
todaysDate = datetime.datetime.today().strftime('%Y-%m-%d')
searchObj = re.search(r'.*memberOf=CN=(.*?),', VAR_LDAP_GROUP, re.M | re.I)
if searchObj:
    ldapgroup = searchObj.group(1)
html = "<html><head><style>body { font-family: sans-serif; font-size: 12.7px; }"
html += "table { font-family: sans-serif; font-size: 12px; min-width: 50px}</style></head><body>"
html += """<div><table border="1" style="border-collapse: collapse" cellpadding="5"<tbody><tr>"""
html += """<th style="text-align: center; background: rgb(204,0,0); color: white; font-size: 14px" colspan="4">"""
html += """Jabber User and Compliance Summary</th></tr><tr>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>Active Directory Group"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>Total Users</b></th>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>Compliant</b></th>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>Non-Compliant</b></th>"""
html += "<tr>"
html += "<td>{0}</td>".format(ldapgroup)
html += "<td>{0}</td>".format(len(ldapuserlist))
html += "<td>{0}</td>".format(len(compliant))
html += "<td>{0}</td>".format(len(noncompliant))
html += "</tr>"
html += "</tbody></table></div><br/><br/>"

html += """<div><table border="1" style="border-collapse: collapse" cellpadding="5"><tbody><tr>"""
html += """<th style="text-align: center; background: rgb(204,0,0); color: white; font-size: 14px" colspan="7">"""
html += """Jabber User and Compliance Report</th></tr><tr>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>UserID</b></th>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>First Name</b></th>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>Last Name</b></th>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>Home Cluster</b></th>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>IM&P Status</b></th>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>Service Profile</b></th>"""
html += """<th style="text-align: left; background: rgb(204,0,0); color:white"><b>Compliance Status</b></th>"""
html += "</tr>"

for ldapuser in ldapusers:
    html += "<tr>"
    html += "<td>{0}</td>".format(ldapuser)
    html += "<td>{0}</td>".format(ldapusers[ldapuser]['firstName'])
    html += "<td>{0}</td>".format(ldapusers[ldapuser]['lastName'])
    html += "<td>{0}</td>".format(ldapusers[ldapuser]['udsHomeCluster'])
    html += "<td>{0}</td>".format(ldapusers[ldapuser]['imAndPresenceEnable'])
    html += "<td>{0}</td>".format(ldapusers[ldapuser]['serviceProfile']['_value_1'])
    html += "<td>{0}</td>".format(ldapusers[ldapuser]['complianceStatus'])
    html += "</tr>"

html += "</tbody></table></div></body></html>"

# Create Excel Attachment of Report Data
logger.info('Creating Excel Attachment')
workbookname = "{0} Compliance Report.xlsx".format(todaysDate)
workbook = xlsxwriter.Workbook(workbookname)
bold = workbook.add_format({'bold': True})
worksheet = workbook.add_worksheet()
badformat = workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})  #  Light red fill with dark red text
goodformat = workbook.add_format({'bg_color': '#C6EFCE', 'font_color': '#006100'}) #  Green fill with dark green text
worksheet.write('A1', 'UserID', bold)
worksheet.write('B1', 'First Name', bold)
worksheet.write('C1', 'Last Name', bold)
worksheet.write('D1', 'UDS Home Cluster', bold)
worksheet.write('E1', 'IM & Presence Enabled', bold)
worksheet.write('F1', 'Service Profile', bold)
worksheet.write('G1', 'Compliance Status', bold)
row = 1
col = 0
for ldapuser in ldapusers:
    worksheet.write(row, col, ldapuser)
    worksheet.write(row, col + 1, ldapusers[ldapuser]['firstName'])
    worksheet.write(row, col + 2, ldapusers[ldapuser]['lastName'])
    worksheet.write(row, col + 3, ldapusers[ldapuser]['udsHomeCluster'])
    worksheet.write(row, col + 4, ldapusers[ldapuser]['imAndPresenceEnable'])
    worksheet.write(row, col + 5, ldapusers[ldapuser]['serviceProfile']['_value_1'])
    worksheet.write(row, col + 6, ldapusers[ldapuser]['complianceStatus'])
    row += 1
worksheet.set_column('A:G', 30)
worksheet.autofilter('A1:G{0}'.format(row + 1))
worksheet.conditional_format('G2:G{0}'.format(row + 1), {'type': 'cell', 'criteria': '==',
                                                         'value': '"Compliant"', 'format': goodformat})
worksheet.conditional_format('G2:G{0}'.format(row + 1), {'type': 'cell', 'criteria': '==',
                                                         'value': '"Non-Compliant"', 'format': badformat})
workbook.close()

# Send HTML Results by Email
logger.info('Sending Report')
message = Email(VAR_MAIL_SERVER)
message.setFrom(VAR_MAIL_SENDER)
message.setSubject("CDW Unified Communications Compliance Audit for " + todaysDate)
for recipient in VAR_MAIL_RECIPIENT.split(","):
    message.addRecipient(recipient)
message.addAttachment(workbookname)
message.setHtmlBody(html)
message.send()
logger.info('Finished CDW Unified Communications Compliance Auditor')

# Cleaning Up
logger.info('Cleaning Up')
try:
    os.remove(workbookname)
    os.remove("sqlite_{0}.db".format(config["cucm"]["cluster1"]["server_ip"]))
    os.remove("sqlite_{0}.db".format(config["cucm"]["cluster2"]["server_ip"]))
    os.remove("sqlite_{0}.db".format(config["cucm"]["cluster3"]["server_ip"]))
    os.remove("sqlite_{0}.db".format(config["cucm"]["cluster4"]["server_ip"]))
    os.remove("sqlite_None.db")
except OSError:
    pass
