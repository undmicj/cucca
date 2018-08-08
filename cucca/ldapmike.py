import sys
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPCursorError
import ast

# Define Auth Info
server_name = '192.168.10.10'
domain_name = 'ciscocollab.ninja'
user_name = 'svc-ldap'
password = 'Ciscocollab41!'

#format_string = '{:40}   {}'
#print(format_string.format('Group', 'Description'))

# Set Server Info
server = Server(server_name, get_info=None)
# server = Server('dc01.ciscocollab.ninja')

# Connect to Server
conn = Connection(server, user="svc-ldap@ciscocollab.ninja",password="Ciscocollab41!",auto_bind=AUTO_BIND_NO_TLS,check_names=False)
# conn = Connection(server, user="svc-ldap@ciscocollab.ninja",password="Ciscocollab41!",auto_bind=AUTO_BIND_NO_TLS,check_names=True)
# conn = Connection(server, user='{}\\{}'.format(domain_name, user_name), password=password, authentication=NTLM, auto_bind=True)
#  No Filter
#conn.search(search_base='DC=ciscocollab,DC=ninja',search_filter='(objectCategory=person)', search_scope=SUBTREE, size_limit=0)
#conn = Connection(
#    server,
#    user='{}\\{}'.format(domain_name, user_name),
#    password=password
#    auto_bind=AUTO_BIND_NO_TLS,
#    check_names=True
#)

print("LDAP Connecton complete")


#  Search With Filter by Group WebEx Users
conn.search(search_base='DC=ciscocollab,DC=ninja',search_filter='(&(memberof=CN=WebEx Users,CN=Users,DC=ciscocollab,DC=ninja))', attributes='sAMAccountName',search_scope=SUBTREE, size_limit=0)


result = ast.literal_eval(conn.response_to_json())

# ldapusers = {} <-- REMOVE
ldapuser = []
# print(type(result))


if result['entries'] is not None:
        for entry in result['entries']: # user is a list of dictionaries, containing user info
            #print(entry['attributes']['sAMAccountName'])
            ldapuser.append(entry['attributes']['sAMAccountName'])
            #add2dict = entry['attributes']['sAMAccountName']
            #print(type(add2dict))
            #users[add2dict] = {}
            #users[user] = {}
            #users[entry['attributes']] = {}  # Adds to the users dictionary a blank dictionary based on the name of the value of user['userid']
            #users[user['userid']]['uuid'] = user['uuid'] #  Adds uuid key
            #users[user['userid']]['firstName'] = user['firstName']
            #users[user['userid']]['lastName'] = user['lastName']
            #users[user['userid']]['homeCluster'] = user['homeCluster']
            #users[user['userid']]['imAndPresenceEnable'] = user['imAndPresenceEnable']
            #users[user['userid']]['serviceProfile'] = user['serviceProfile']
# print(ldapuser)

ldapuserlist = [''.join(x) for x in ldapuser] # This converts user(list of lists) to just a list of users
print(ldapuserlist)

# Moved below to cucca.py
# for entry in ldapuserlist:
#    ldapusers[entry] = {}  # Creates a dictonary per user as a key in the dictonary users

# for u_id, u_info in ldapusers.items():
#     print("\nPerson ID:", u_id)
#     for key in u_info:
#         print(key + ':', u_info[key])
# End Moved Code


#conn.search('dc={},dc=local'.format(domain_name), '(objectclass=group)', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])

#for e in sorted(conn.entries):
#    try:
#        desc = e.description
#    except LDAPCursorError:
#        desc = ""
#    print(format_string.format(str(e.name), desc))

#ldap3.Reader(c, person, '(&(member=CN=myuser_in_full_name,OU=xxx,OU=xxxxxx,DC=mydomain,DC=com)(objectClass=group))', 'dc=mydomain,dc=com').search()
