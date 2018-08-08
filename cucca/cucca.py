from axltoolkit import AxlToolkit
from credentials import user, password, platform_user, platform_password
from ldap import ldapuserlist
import xml.etree.ElementTree as ET
import requests


# Be sure to update the credentials.py file with your AXL User and Platform User credentials

# Put the IP address of your UCM Publisher
ucm_ip = '192.168.10.220'

axl = AxlToolkit(username=user, password=password, server_ip=ucm_ip, tls_verify=False, version='12.0')

def uds(username):
    r = requests.get("https://cucm2.ciscocollab.ninja:8443/cucm-uds/clusterUser?username=" + username, verify=False)
    #print(r.status_code)
    # print(r.headers)
    #print(r.content)

    root = ET.fromstring(r.content)

    # for child in root.iter('*'):
        # print(child.tag)
    for child in root.iter('result'):
        if child.attrib['found'] == 'false':
            print(username, "not found in UDS!")
            userHomeCluster = "NO UDS"
            return userHomeCluster
    for item in root.iter('homeCluster'):
        userHomeCluster = item.text
    return userHomeCluster

# ldapuserlist = ["munderwood", "cclouse"]  # this will be generated off of Clouse's LDAP Output
ldapusers = {}


for ldapuser in ldapuserlist:
    ldapusers[ldapuser] = {}
    # COMPLETE - querey UDS for home cluster and store the value
    ldapusers[ldapuser]['udsHomeCluster'] = uds(ldapuser)
    #
    # when homecluster is found add that entry to the user dictionary and then query the correct axl server
    # DO WE NEED TO MOVE LINE 13 DOWN HERE, HOW DO WE HANDLE THIS
    #
    result = axl.list_users(userid=ldapuser)  # result = axl.list_users(userid="munderwood") # If you set userid to "%" it returns all users
    if result['return'] is not None:
        for user in result['return']['user']:  # user is a list of dictionaries, containing user info
            # ldapusers[user['userid']]['uuid'] = user['uuid']  # Adds uuid key
            ldapusers[user['userid']]['firstName'] = user['firstName']
            ldapusers[user['userid']]['lastName'] = user['lastName']
            ldapusers[user['userid']]['homeCluster'] = user['homeCluster']
            ldapusers[user['userid']]['imAndPresenceEnable'] = user['imAndPresenceEnable']
            ldapusers[user['userid']]['serviceProfile'] = user['serviceProfile']


# Print User Dictionaries
for u_id, u_info in ldapusers.items():
    print("\nPerson ID:", u_id)
    for key in u_info:
        print(key + ':', u_info[key])

print("Done.")

#print(users)


