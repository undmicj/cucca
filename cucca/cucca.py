from axltoolkit import AxlToolkit
from ldap3 import Server, Connection, Reader, ObjectDef, SUBTREE, BASE, ALL_ATTRIBUTES, ObjectDef, AttrDef, Reader, Entry, Attribute, OperationalAttribute
#from ldap import ldapuserlist, numberofldapusers, VAR_LDAP_GROUP
import xml.etree.ElementTree as ET
import requests
import yaml
import smtplib
import datetime
import email
import ast

### INITIALIZE CONFIG FILE AND READ IN VARIABLES
print("Reading Configuration File")
with open("config.yml", "r") as ymlfile:
    config = yaml.load(ymlfile)

VAR_LDAP_SERVER = config["ldap"]["server"]
VAR_LDAP_PORT = config["ldap"]["port"]
VAR_LDAP_SSL = config["ldap"]["ssl"]
VAR_LDAP_USERNAME = config["ldap"]["username"]
VAR_LDAP_PASSWORD = config["ldap"]["password"]
VAR_LDAP_SEARCH_BASE = config["ldap"]["searchbase"]
VAR_LDAP_GROUP = config["ldap"]["querygroup"]
VAR_LDAP_ATTRIBUTE = config["ldap"]["attribute"]
VAR_MAIL_SERVER = config["mail"]["server"]
VAR_MAIL_PORT = config["mail"]["port"]
VAR_MAIL_AUTH_REQ = config["mail"]["auth_required"]
VAR_MAIL_AUTH_USERNAME = config["mail"]["auth_username"]
VAR_MAIL_AUTH_PASSWORD = config["mail"]["auth_password"]
VAR_MAIL_SENDER = config["mail"]["sender"]
VAR_MAIL_RECIPIENT = config["mail"]["recipient"]
VAR_UDS_FQDN = config["cucm"]["primary_uds_server"]

print("Reading Configuration File Complete")

def ldaplookup():
    # Connect to LDAP Services & Pull Data
    print("Capturing Group Membership")
    server = Server(VAR_LDAP_SERVER, port=VAR_LDAP_PORT, use_ssl=VAR_LDAP_SSL, get_info=None)
    ldapbind = Connection(server, user=VAR_LDAP_USERNAME, password=VAR_LDAP_PASSWORD, auto_bind=True)
    ldapbind.search(search_base=VAR_LDAP_SEARCH_BASE, search_filter=VAR_LDAP_GROUP, attributes=VAR_LDAP_ATTRIBUTE, search_scope=SUBTREE, size_limit=0)

    # Parsing LDAP Data
    print("Parsing Group Membership")
    result = ast.literal_eval(ldapbind.response_to_json())
    ldapuser = []
    if result['entries'] is not None:
        for entry in result['entries']:  # user is a list of dictionaries, containing user info
            ldapuser.append(entry['attributes']['sAMAccountName'])
    ldapuserlist = [''.join(x) for x in ldapuser]  # This converts user(list of lists) to just a list of users
    print("Parsing Group Membership Completed")
    return ldapuserlist

def udslookup(username):
    r = requests.get("https://" + VAR_UDS_FQDN + ":8443/cucm-uds/clusterUser?username=" + username, verify=False)
    # print("UDS http URL for user", username, "is", "https://" + VAR_UDS_FQDN + ":8443/cucm-uds/clusterUser?username=" + username)
    # print(r.status_code)
    # print(r.headers)
    # print(r.content)

    root = ET.fromstring(r.content)
    for child in root.iter('result'):
        if child.attrib['found'] == 'false':
            print(username, "not found in UDS!")
            userHomeCluster = "NO UDS"
            return userHomeCluster
    for item in root.iter('homeCluster'):
        userHomeCluster = item.text
    return userHomeCluster

def email(VAR_MAIL_SERVER,VAR_MAIL_PORT):
    # Prepare Results to Email Recipient
    print('Preparing Email')
    todaysDate = datetime.datetime.today().strftime('%Y-%m-%d')
    #message = EmailMessage()
    #message ['Subject'] = "CDW Unified Communications Compliance Audit for " + todaysDate
    #message ['From'] = VAR_MAIL_SENDER
    #message ['To'] = VAR_MAIL_RECIPIENT
    #message = MIMEMultipart()
    #messagebody = 'CDW Unified Communications Compliance Audit for ' + todaysDate + '\n'
    # 'There are currently ' + numberofldapusers + 'associates in ' + VAR_LDAP_GROUP + '\n' +
    #(todaysDate,numberofldapusers,VAR_LDAP_GROUP, )
    #'There are currently ' + 'COMPLIANT associates in ' + VAR_LDAP_GROUP + '\n' +
    #'There are currently ' + 'NON-COMPLIANT associates in ' + VAR_LDAP_GROUP + '\n' +
    #'There are currently ' + 'UNPROVISIONED associates in ' + VAR_LDAP_GROUP
    #messagebody = MIMEText(messagebody)
    #message.attach(messagebody)
    #message.set_content(messagebody)

    #Send Results to Email Recipient
    print('Preparing Email Completed')

    try:
        print('Sending Report')
        mailserver = smtplib.SMTP(VAR_MAIL_SERVER, VAR_MAIL_PORT)
        mailserver.ehlo()
        mailserver.starttls()
        mailserver.ehlo()
        if VAR_MAIL_AUTH_REQ is True:
            # If SMTP Authentication is required, login to mail server with specified credentials
            mailserver.login(VAR_MAIL_AUTH_USERNAME, VAR_MAIL_AUTH_PASSWORD)
        else:
            # If SMTP Authentication is not required, carry on
            mailserver.set_debuglevel(0)
            mailserver.send_message(message)
            mailserver.quit()
        print('Sending Report Complete')
    except:
        print('Error: Unable to Send Report')

### CREATE AXL INSTANCES
axl1 = AxlToolkit(username=config["cucm"]["cluster1"]["username"], password=config["cucm"]["cluster1"]["password"], server_ip=config["cucm"]["cluster1"]["server_ip"], tls_verify=False, version='12.0')
axl2 = AxlToolkit(username=config["cucm"]["cluster2"]["username"], password=config["cucm"]["cluster2"]["password"], server_ip=config["cucm"]["cluster2"]["server_ip"], tls_verify=False, version='12.0')
axl3 = AxlToolkit(username=config["cucm"]["cluster3"]["username"], password=config["cucm"]["cluster3"]["password"], server_ip=config["cucm"]["cluster3"]["server_ip"], tls_verify=False, version='12.0')
axl4 = AxlToolkit(username=config["cucm"]["cluster4"]["username"], password=config["cucm"]["cluster4"]["password"], server_ip=config["cucm"]["cluster4"]["server_ip"], tls_verify=False, version='12.0')

### EXECUTE LDAP LOOKUP, UDS LOOKUP, AXL LOOKUP
ldapuserlist = ldaplookup()
numberofldapusers = len(ldapuserlist)
ldapusers = {}
for ldapuser in ldapuserlist:
    ldapusers[ldapuser] = {}
    ldapusers[ldapuser]['udsHomeCluster'] = udslookup(ldapuser)  # Query UDS for home cluster and store the value in the user dict
    # print("UDS URL SAYS HOME CLUSTER IS", ldapusers[ldapuser]['udsHomeCluster'], "FOR", ldapuser)
    if ldapusers[ldapuser]['udsHomeCluster'] == "ciscocucmpub.ciscocollab.ninja":
        result = axl1.list_users(userid=ldapuser)
    elif ldapusers[ldapuser]['udsHomeCluster'] == "cucm2.ciscocollab.ninja":
        result = axl2.list_users(userid=ldapuser)
    elif ldapusers[ldapuser]['udsHomeCluster'] == "cucm3.ciscocollab.ninja":
        result = axl3.list_users(userid=ldapuser)
    elif ldapusers[ldapuser]['udsHomeCluster'] == "cucm4.ciscocollab.ninja":
        result = axl4.list_users(userid=ldapuser)
    else:
        print("No AXL details for homecluster:", ldapusers[ldapuser]['udsHomeCluster'])
    if result['return'] is not None:
        for user in result['return']['user']:  # user is a list of dictionaries, containing user info
            # ldapusers[user['userid']]['uuid'] = user['uuid']  # Adds uuid key
            ldapusers[user['userid']]['firstName'] = user['firstName']
            ldapusers[user['userid']]['lastName'] = user['lastName']
            ldapusers[user['userid']]['homeCluster'] = user['homeCluster']
            ldapusers[user['userid']]['imAndPresenceEnable'] = user['imAndPresenceEnable']
            ldapusers[user['userid']]['serviceProfile'] = user['serviceProfile']

### PRINT USER DICTIONARIES AND CAPTURE COMPLIANCE STATUS
noncompliant =[]
compliant = []
for u_id, u_info in ldapusers.items():
    # print("\nuserid:", u_id)
    for key in u_info:
        # print(key + ':', u_info[key])
        if key == 'imAndPresenceEnable':
            if u_info[key] == 'true':
                noncompliant.append(u_id)
                # print(u_id, "is enabled for IM&P")

### DISPLAY COMPLIANCE
print("There are %s users in the %s distribution list" % (numberofldapusers, VAR_LDAP_GROUP))
print("...")
print("There are %s non-compliant users" % len(noncompliant))
print("The following users are non-compliant:")
for user in noncompliant:
    print(user)
print("...")
print("There are %s complaint users" % len(compliant))
print("The following users are compliant:")
for user in compliant:
    print(user)
print("...")
print("Done.")

### SEND RESULTS VIA EMAIL
email(VAR_MAIL_SERVER,VAR_MAIL_PORT)