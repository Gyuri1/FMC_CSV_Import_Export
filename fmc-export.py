#
# FMC ACP export to CSV tool 
#
#  Version: 2.0
#  Updated:  applications category 
#            user category 

# import required dependencies
import sys
import csv
import json

# FMC Credential file
import fmc_config

# FMC Class
from fmc_class import fmc


# Found Object
# True: found, False: not found
def find_object(object_db, obj_name, obj_type):
    result=False
    for i in object_db:
        if i['name'] == obj_name and i['type'] == obj_type:
            result=True
    return result        

# Store an Object
def store_an_object(object_db, i):
    if not find_object(object_db, i['name'], i['type']):
        object_db.append(dict({ 'name': i['name'], 'id': i['id'],'type': i['type']}))
       

# Parse ACP Rule, return list
def parse_rule(rule, object_db):
    # mandatory fields
    R_NAME      = rule['name']
    R_ACTION    = rule['action']
    R_ENABLED   = rule['enabled']
    R_SECTION   = ''
    R_CATEGORY  = ''
    R_SRC_ZN    = ''
    R_DST_ZN    = ''
    R_SRC_IP    = ''
    R_DST_IP    = ''
    R_VLAN      = ''
    R_USERS     = ''
    R_APPS      = ''
    R_URLS      = ''
    R_SRC_P     = ''
    R_DST_P     = ''
    R_SRC_SGT   = ''
    R_DST_SGT   = ''
    R_SRC_DOBJ  = ''
    R_DST_DOBJ  = ''
    R_ENDPOINT  = ''
    R_NETWORKA  =''
    R_IPS       = ''
    R_FILE      = ''
    R_VAR       = ''
    R_LOGB      = ''
    R_LOGE      = '' 
    R_SENDE     = ''
    R_SYSLOG    = ''
    R_SNMP      = ''
    R_COMMENT   = ''

    if 'section' in rule['metadata']:
        R_SECTION = rule['metadata']['section']

    if 'category' in rule['metadata']:
        R_CATEGORY = rule['metadata']['category']

     # Source Zones
    if 'sourceZones' in rule:
        temp_list =[]
        for i in rule['sourceZones']['objects']:
            temp_list.append(i['name'])  
            store_an_object(object_db, i)

        if len(temp_list) > 1:
            R_SRC_ZN = '; '.join(temp_list)
        else:
            R_SRC_ZN = temp_list[0]

    # Destination Zones
    if 'destinationZones' in rule:
        temp_list =[]
        for i in rule['destinationZones']['objects']:
            temp_list.append(i['name'])  
            store_an_object(object_db, i)

        if len(temp_list) > 1:
            R_DST_ZN = '; '.join(temp_list)
        else:
            R_DST_ZN = temp_list[0]


    # Source Networks
    if 'sourceNetworks' in rule:
        #print(rule['sourceNetworks'])
        lits = ''
        objs = ''
        # Literals do not contain real objects with value
        # We do not need to save the object.    
        if 'literals' in rule['sourceNetworks']:
            temp_list = [i['value'] for i in rule['sourceNetworks']['literals']]
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]

        if 'objects' in rule['sourceNetworks']:
            temp_list =[]
            for i in rule['sourceNetworks']['objects']:
                temp_list.append(i['name'])  
                store_an_object(object_db, i)

            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]

        if (lits != '') and (objs != ''):
            R_SRC_IP = '; '.join([lits,objs])
        elif lits != '':
            R_SRC_IP = lits
        elif objs != '':
            R_SRC_IP = objs

    # Destination Networks
    if 'destinationNetworks' in rule:
        lits = ''
        objs = ''
        if 'literals' in rule['destinationNetworks']:
            temp_list = [i['value'] for i in rule['destinationNetworks']['literals']]
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]

        if 'objects' in rule['destinationNetworks']:
            temp_list =[]
            for i in rule['destinationNetworks']['objects']:
                temp_list.append(i['name'])  
                store_an_object(object_db, i)

            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]

        if (lits != '') and (objs != ''):
            R_DST_IP = '; '.join([lits,objs])
        elif lits != '':
            R_DST_IP = lits
        elif objs != '':
            R_DST_IP = objs

    # VLAN Tags
    if 'vlanTags' in rule:
        lits = ''
        objs = ''
        if 'literals' in rule['vlanTags']:
            temp_list = []
            for i in rule['vlanTags']['literals']:
                if i['startTag'] == i['endTag']:
                    temp_list.append(str(i['startTag']))
                else:
                    temp_list.append(f'{i["startTag"]}-{i["endTag"]}')
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]
        if 'objects' in rule['vlanTags']:
            temp_list =[]
            for i in rule['vlanTags']['objects']:
                temp_list.append(i['name'])  
                store_an_object(object_db, i)

            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]

        if (lits != '') and (objs != ''):
            R_VLAN = '; '.join([lits,objs])
        elif lits != '':
            R_VLAN = lits
        elif objs != '':
            R_VLAN = objs
    # Users
    if 'users' in rule:
        temp_list = []

        #print("users:", rule['users'])
        for i in rule['users']['objects']:
            store_an_object(object_db, i)
            if 'realm' in i:
                store_an_object(object_db, i['realm'])
            # all user case ( domain\*) 
            if i['type'] == 'Realm':
                temp_list.append(str(i['name'])+"/" +'*')
            else:    
                temp_list.append(str(i['realm']['name'])+"/" + i['name'])

        if len(temp_list) > 1:
            R_USERS = '; '.join(temp_list)
        else:
            R_USERS = temp_list[0]

        #print("R_USERS:", R_USERS)
         

        """    
        if 'id' in rule:
            store_an_object(object_db, { 'name': "ID_POLICY_ID", 'id': rule['id'],'type': "ID_POLICY_ID"})
        else:
            print("ERROR: Identity policy ID not found!")
        """    


    # Application Filters
    if 'applications' in rule:

        #print(">>APP", rule['applications'])

        R_APPS=''

        if 'applications' in rule['applications']:
            temp_list =[]
            for i in rule['applications']['applications']:
                    temp_list.append(i['name'])  
                    store_an_object(object_db, i)

            if len(temp_list) > 1:
                R_APPS = '; '.join(temp_list)
            else:
                R_APPS = temp_list[0]

        if 'inlineApplicationFilters' in rule['applications']:

            temp_list =[]
            for i in rule['applications']['inlineApplicationFilters']:
                    if 'search' in i:
                        temp_list.append('Filter:'+i['search'])

                    if 'categories' in i:
                        for j in i['categories']:
                            temp_list.append('Categories:'+j['name'])
                            store_an_object(object_db, j) 
                    if 'risks' in i:
                        for j in i['risks'] :
                            temp_list.append('Risks:'+j['name']) 
                            store_an_object(object_db, j)

                    if 'applicationTypes' in i:
                        for j in i['applicationTypes'] :
                            temp_list.append('Types:'+j['name']) 
                            store_an_object(object_db, j)

                    if 'tags' in i:
                        for j in i['tags'] :
                            temp_list.append('Tags:'+j['name']) 
                            store_an_object(object_db, j)

                    if 'productivities' in i:
                        for j in i['productivities'] :
                            temp_list.append('Business Relevance:'+j['name']) 
                            store_an_object(object_db, j)        

            if len(temp_list) > 1:
                appfilter = '; '.join(temp_list)
            else:
                appfilter = temp_list[0]

        if R_APPS:
            R_APPS = R_APPS+ "; " + appfilter
        else:
            R_APPS = appfilter


    # Source Ports
    if 'sourcePorts' in rule:
        #print(rule['sourcePorts'])
        lits = ''
        objs = ''
        if 'literals' in rule['sourcePorts']:
            temp_list = []
            for i in rule['sourcePorts']['literals']:
                if i['protocol'] == '6':
                    temp_list.append(f'TCP:{i["port"]}')
                elif i['protocol'] == '17':
                    temp_list.append(f'UDP:{i["port"]}')
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]

        if 'objects' in rule['sourcePorts']:
            temp_list =[]
            for i in rule['sourcePorts']['objects']:
                temp_list.append(i['name'])  
                store_an_object(object_db, i)
            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]

        if (lits != '') and (objs != ''):
            R_SRC_P = '; '.join([lits,objs])
        elif lits != '':
            R_SRC_P = lits
        elif objs != '':
            R_SRC_P = objs

    # Destination Ports
    if 'destinationPorts' in rule:
        #print(rule['destinationPorts'])
        lits = ''
        objs = ''
        if 'literals' in rule['destinationPorts']:
            temp_list = []
            for i in rule['destinationPorts']['literals']:
                if i['protocol'] == '6':
                    temp_list.append(f'TCP:{i["port"]}')
                elif i['protocol'] == '17':
                    temp_list.append(f'UDP:{i["port"]}')
                else:
                    temp_list.append(i['protocol'])         
            if len(temp_list) > 1:
                lits = '; '.join(temp_list)
            else:
                lits = temp_list[0]
        if 'objects' in rule['destinationPorts']:
            temp_list =[]
            for i in rule['destinationPorts']['objects']:
                temp_list.append(i['name'])  
                store_an_object(object_db, i)

            if len(temp_list) > 1:
                objs = '; '.join(temp_list)
            else:
                objs = temp_list[0]

        if (lits != '') and (objs != ''):
            R_DST_P = '; '.join([lits,objs])
        elif lits != '':
            R_DST_P = lits
        elif objs != '':
            R_DST_P = objs

    # URL Reputation Filters
    if 'urls' in rule:
        #print("\rURLs:", rule['urls'])
        #print("*"*40)
        lits = ''
        cats = ''
        if 'literals' in rule['urls']:
            temp_list = []
            for i in rule['urls']['literals']:
                temp_list = [i['url'] for i in rule['urls']['literals']]
                if len(temp_list) > 1:
                    lits = '; '.join(temp_list)
                else:
                    lits = temp_list[0]

        if 'urlCategoriesWithReputation' in rule['urls']:
            temp_list=[]
            for i in rule['urls']['urlCategoriesWithReputation']:
                #print(">>>", i)
                if i['category']['name'] == "Uncategorized":
                    temp_list.append("Uncategorized")
                # cut the cat name if it contains ','  
                # FMC has ONLY one category with ',': "Conventions, Conferences and Trade Shows" 
                elif ','in i['category']['name']:
                    # Since category names contain '(' characters, we need to use '['     
                    temp_list.append( i['category']['name'].split(',')[0]+'['+i['reputation']+']')
                else:
                    temp_list.append(i['category']['name']+'['+i['reputation']+']')
            
                store_an_object(object_db, i['category'])   

            if len(temp_list) > 1:
                cats = '; '.join(temp_list)
            else:
                cats = temp_list[0]    

        if (lits != '') and (cats != ''):
            R_URLS = '; '.join([lits,cats])
        elif lits != '':
            R_URLS = lits
        elif cats != '':
            R_URLS = cats

        #print(">> URLs:", R_URLS)    
      
    # Source SGTs
    if 'sourceSecurityGroupTags' in rule:
        temp_list=[]
        for i in rule['sourceSecurityGroupTags']['objects']:
            temp_list.append(i['name']) 
            store_an_object(object_db, i)

        if len(temp_list) > 1:
            R_SRC_SGT = '; '.join(temp_list)
        else:
            R_SRC_SGT = temp_list[0]

    # Destination SGTs
    if 'destinationSecurityGroupTags' in rule:
        temp_list=[]
        for i in rule['destinationSecurityGroupTags']['objects']:
            temp_list.append(i['name']) 
            store_an_object(object_db, i)
      
        if len(temp_list) > 1:
            R_DST_SGT = '; '.join(temp_list)
        else:
            R_DST_SGT = temp_list[0]

    # sourceDynamicObjects
    if 'sourceDynamicObjects' in rule:
        temp_list =[]
        if 'objects' in rule['sourceDynamicObjects']:
            for i in rule['sourceDynamicObjects']['objects']:
                temp_list.append(i['name'])
                store_an_object(object_db, i)
            if len(temp_list) > 1:
                R_SRC_DOBJ = '; '.join(temp_list)
            else:
                R_SRC_DOBJ = temp_list[0]   
    
    # destinationDynamicObjects
    if 'destinationDynamicObjects' in rule:
        temp_list =[]
        if 'objects' in rule['destinationDynamicObjects']:
            for i in rule['destinationDynamicObjects']['objects']:
                temp_list.append(i['name'])
                store_an_object(object_db, i)
            if len(temp_list) > 1:
                R_DST_DOBJ = '; '.join(temp_list)
            else:
                R_DST_DOBJ = temp_list[0]
    
    # networkAccessDeviceIPs
    if 'networkAccessDeviceIPs' in rule:
        temp_list =[]
        if 'objects' in rule['networkAccessDeviceIPs']:
            for i in rule['networkAccessDeviceIPs']['objects']:
                temp_list.append(i['name'])
                store_an_object(object_db, i)
            if len(temp_list) > 1:
                R_NETWORKA = '; '.join(temp_list)
            else:
                R_NETWORKA = temp_list[0]
   

    # endPointDeviceTypes
    if 'endPointDeviceTypes' in rule:
        temp_list =[]
        for i in rule['endPointDeviceTypes']:
            temp_list.append(i['name'])
            store_an_object(object_db, i)
        if len(temp_list) > 1:
            R_ENDPOINT = '; '.join(temp_list)
        else:
            R_ENDPOINT = temp_list[0]


    # IPS Policy
    if 'ipsPolicy' in rule:
        R_IPS = rule['ipsPolicy']['name']
        store_an_object(object_db, rule['ipsPolicy'])

    # File Policy
    if 'filePolicy' in rule:
        R_FILE = rule['filePolicy']['name']
        store_an_object(object_db, rule['filePolicy'])

    # File Policy
    if 'variableSet' in rule:
        R_VAR = rule['variableSet']['name'] 
        store_an_object(object_db, rule['variableSet'])

    # sendEventsToFMC
    if 'sendEventsToFMC' in rule:
        R_SENDE = rule['sendEventsToFMC']

    # enableSyslog
    if 'enableSyslog' in rule:
        R_SYSLOG = rule['enableSyslog']           

    # logBegin
    if 'logBegin' in rule:
        R_LOGB = rule['logBegin'] 

    # logEnd
    if 'logEnd' in rule:
        R_LOGE = rule['logEnd'] 

    # SNMP Config
    if 'snmpConfig' in rule:
        R_SNMP = rule['snmpConfig']['name'] 
        store_an_object(object_db, rule['snmpConfig'])    

    # Comments
    # syntax: comment(user)[date]
    if 'commentHistoryList' in rule:
        temp_list = []
        for i in rule['commentHistoryList']:
            temp_list.append(i['comment']+'('+i['user']['name']+')'+'['+i['date']+']')
        if len(temp_list) > 1:
            R_COMMENT = '; '.join(temp_list)
        else:
            R_COMMENT = temp_list[0] 

    line={}
    line['name']                         = R_NAME
    line['category']                     = R_CATEGORY     
    line['action']                       = R_ACTION
    line['section']                      = R_SECTION
    line['enabled']                      = R_ENABLED 
    line['sourceZones']                  = R_SRC_ZN
    line['destinationZones']             = R_DST_ZN
    line['sourceNetworks']               = R_SRC_IP
    line['destinationNetworks']          = R_DST_IP
    line['sourcePorts']                  = R_SRC_P
    line['destinationPorts']             = R_DST_P
    line['vlanTags']                     = R_VLAN
    line['users']                        = R_USERS
    line['applications']                 = R_APPS
    line['urls']                         = R_URLS
    line['sourceSecurityGroupTags']      = R_SRC_SGT
    line['destinationSecurityGroupTags'] = R_DST_SGT
    line['sourceDynamicObjects']         = R_SRC_DOBJ
    line['destinationDynamicObjects']    = R_DST_DOBJ
    line['endPointDeviceTypes']          = R_ENDPOINT
    line['networkAccessDeviceIPs']       = R_NETWORKA
    line['ipsPolicy']                    = R_IPS
    line['filePolicy']                   = R_FILE
    line['variableSet']                  = R_VAR
    line['logBegin']                     = R_LOGB
    line['logEnd']                       = R_LOGE
    line['sendEventsToFMC']              = R_SENDE 
    line['enableSyslog']                 = R_SYSLOG
    line['snmpConfig']                   = R_SNMP
    line['commentHistoryList']           = R_COMMENT

    return line

def main():

    # Set variables for execution.
    # Make sure your credentials are correct.
    device   = fmc_config.host
    username = fmc_config.admin
    password = fmc_config.password

    policy_filename= "_policy"
    object_filename= "_objects"

    # With child domain (note the spacing):
    # domain = 'Global/ NAME-OF-CHILD'
    target_domain = ''
    target_acp = ''
    acp_id=''
    cli_params= False
    object_db=[]

    if (len(sys.argv) != 1):
        if (len(sys.argv) != 3) :
            print(f"python {sys.argv[0]} Domain_name AccessControlPolicy_name")
            exit()

    if (len(sys.argv) == 3):
       target_domain = sys.argv[1]
       target_acp = sys.argv[2]
       cli_params = True


    # Initialize a new api object
    print("FMC authentication for this FMC:", device)
    api = fmc(host = device, username=username, password=password)
    api.tokenGeneration(target_domain)
    print("Token received.")

    if cli_params == False:
        print("Authorized domains:")
        for domain in api.domains["domains"]:
            print("Domain name:",domain["name"])
        if target_domain =="":
            print("Which is the target domain?")
            target_domain=input()

    for domain in api.domains["domains"]:
        if domain["name"] == target_domain:
            api.uuid= domain['uuid']

    if api.uuid == "":
        print("ERROR: no target domain")
        exit()

    acps = api.get_accesspolicies()

    if cli_params == False:
        print("Access Control Policies:")
        for acp in acps["items"]:
            print("Policy name:", acp["name"] )

        if target_acp =="":
            print("Which is the target Access Control Policy?")
            target_acp=input()

    for acp in acps["items"]:
        if acp["name"] == target_acp:
            acp_id= acp["id"]
        #sprint(">> acp name:",acp['name'])    

    if acp_id == "":
        print(f"ERROR: {target_acp} policy cannot be found!")
        exit()


    with open(target_acp + ".csv", 'w', newline='') as csvfile:
        fieldnames = ['number','name','enabled','action', 'section','category','sourceZones','destinationZones','sourceNetworks','destinationNetworks','vlanTags','users','applications','sourcePorts','destinationPorts','urls','sourceSecurityGroupTags', 'destinationSecurityGroupTags','sourceDynamicObjects', 'destinationDynamicObjects','endPointDeviceTypes','networkAccessDeviceIPs','ipsPolicy','variableSet','filePolicy','logBegin','logEnd','sendEventsToFMC','enableSyslog', 'snmpConfig', 'commentHistoryList' ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        print("Access control policy: {0}".format(target_acp))
        print("-" * 80)

        # Get all access control rules for the access control policy specified 
        acp_rules = api.get_acp_rules(acp_id)
        
        f = open(target_acp + policy_filename +".json", "w")
        f.write(json.dumps(api.getPolicy_details(acp_id), indent = 4))
        f.close()    

        try:
            test1 = acp_rules["items"]
        except KeyError:
            print("ERROR: Empty rule")
            exit()
        
        print("Number of lines: ", len(acp_rules["items"]))
        
        rule_number=1
        with open(target_acp+object_filename + ".csv", 'w', newline='') as objectfile:
            fields = ['name', 'id','type']
            writer_obj = csv.DictWriter(objectfile, fieldnames=fields)
            writer_obj.writeheader()        

            for acp_rule in acp_rules["items"]:
                print("Rule name:", acp_rule["name"])
                # This is for unique rule request, but this is not needed here
                #rule = api.get_acp_rule(acp_id, acp_rule["id"])
                line=parse_rule(acp_rule, object_db)
                line['number'] = rule_number
                writer.writerow(line)
                rule_number=rule_number+1

            for obj in object_db:
                writer_obj.writerow(obj)    
                
        print("-" * 80)    
        print("CSV Rule file created : {0}.csv".format(target_acp))
        print(f"Policy file created: {target_acp+policy_filename}.json")
        print(f"Object file created: {target_acp+object_filename}.csv")


# Stand Alone execution
if __name__ == "__main__":
    main()
