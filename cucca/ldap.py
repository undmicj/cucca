from ldap3 import Server, Connection, Reader, ObjectDef, SUBTREE, BASE, ALL_ATTRIBUTES, ObjectDef, AttrDef, Reader, Entry, Attribute, OperationalAttribute
import yaml
import ast

# Read in Configuration Variables from config.yml
print("Reading Configuration File")
with open('config.yml', 'r') as ymlfile:
    config = yaml.load(ymlfile)

VAR_LDAP_SERVER = config["ldap"]["server"]
VAR_LDAP_PORT = config["ldap"]["port"]
VAR_LDAP_SSL = config["ldap"]["ssl"]
VAR_LDAP_USERNAME = config["ldap"]["username"]
VAR_LDAP_PASSWORD = config["ldap"]["password"]
VAR_LDAP_SEARCH_BASE = config["ldap"]["searchbase"]
VAR_LDAP_GROUP = config["ldap"]["querygroup"]
VAR_LDAP_ATTRIBUTE = config["ldap"]["attribute"]
print("Reading Configuration File Complete")


def ldaplookup():
    # Connect to LDAP Services & Pull Data
    print("Capturing Group Membership")
    server = Server(VAR_LDAP_SERVER, port=VAR_LDAP_PORT, use_ssl=VAR_LDAP_SSL, get_info=None)
    ldapbind = Connection(server, user=VAR_LDAP_USERNAME, password=VAR_LDAP_PASSWORD, auto_bind=True)
    ldapbind.search(search_base=VAR_LDAP_SEARCH_BASE, search_filter=VAR_LDAP_GROUP, attributes=VAR_LDAP_ATTRIBUTE, search_scope=SUBTREE, size_limit=0)

    # Parsing LDAP Data
    print("Parsing Group Membership")
    # ldap_membership_json=(ldapbind.response_to_json())
    result = ast.literal_eval(ldapbind.response_to_json())
    ldapuser = []

    if result['entries'] is not None:
        for entry in result['entries']:  # user is a list of dictionaries, containing user info
            ldapuser.append(entry['attributes']['sAMAccountName'])

    ldapuserlist = [''.join(x) for x in ldapuser]  # This converts user(list of lists) to just a list of users
    numberofldapusers = len(ldapuserlist)
    print("Parsing Group Membership Completed")
    print("...")

ldaplookup()