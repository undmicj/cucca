from axltoolkit import AxlToolkit
from credentials import user, password, platform_user, platform_password, axl_creds
from ldap import ldapuserlist
import xml.etree.ElementTree as ET
import requests
import yaml


def uds(username):
    r = requests.get("https://" + VAR_UDS_FQDN + ":8443/cucm-uds/clusterUser?username=" + username, verify=False)
    print("UDS http URL for user", username, "is", "https://" + VAR_UDS_FQDN + ":8443/cucm-uds/clusterUser?username=" + username)
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


print('Reading Configuration File')
with open('config.yml', 'r') as ymlfile:
    config = yaml.load(ymlfile)
print('Reading Configuration File Complete')

# SET UDS SERVER
VAR_UDS_FQDN = config["uds"]["server"]  # VAR_UDS_FQDN = 'cucm2.ciscocollab.ninja'

# CREATE AXL INSTANCE
axl1 = AxlToolkit(username=config["axl1"]["username"], password=config["axl1"]["password"], server_ip=config["axl1"]["server_ip"], tls_verify=False, version='12.0')
axl2 = AxlToolkit(username=config["axl2"]["username"], password=config["axl2"]["password"], server_ip=config["axl2"]["server_ip"], tls_verify=False, version='12.0')
axl3 = AxlToolkit(username=config["axl3"]["username"], password=config["axl3"]["password"], server_ip=config["axl3"]["server_ip"], tls_verify=False, version='12.0')
axl4 = AxlToolkit(username=config["axl4"]["username"], password=config["axl4"]["password"], server_ip=config["axl4"]["server_ip"], tls_verify=False, version='12.0')


ldapusers = {}

for ldapuser in ldapuserlist:
    ldapusers[ldapuser] = {}
    ldapusers[ldapuser]['udsHomeCluster'] = uds(ldapuser)  # Query UDS for home cluster and store the value in the user dict
    print("UDS URL SAYS HOME CLUSTER IS", ldapusers[ldapuser]['udsHomeCluster'], "FOR", ldapuser)
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


# PRINT USER DICTIONARIES
for u_id, u_info in ldapusers.items():
    print("\nuserid:", u_id)
    for key in u_info:
        print(key + ':', u_info[key])

print("Done.")

#print(users)


# Total Users

# Compliant
# Not enabled for IM&P
# Non-Compliant
# in group, enabled for IM&P

# Unprovisioned
# No UDS
