#
# FMC ACP import from CSV tool 
#
#  Not supported fields:
#   - Object overridable

# TODOs:
#  Handle Policy's PreFilter, Security Intell and SSL Decyrption
#  Check the URLCategory REAL NAME with ;
#  element_name.split(reputation_separator)[0]
#
#  Version 2.0 
#  Updated:


# import required dependencies
import sys
import requests
import json
import csv

# FMC Class
from fmc_class import fmc

# FMC Credential file
import fmc_config


def find_id(object_db, name, obj_type):
    r=''
    for i in object_db:
        if (i['name']==name) and (i['type']== obj_type):
            r=i['id']
    return r     

def find_type(object_db, name):
    r=''
    for i in object_db:
        if (i['name']==name) and (i['type']== 'Host' or i['type']== 'Network' or i['type']== 'Continent' or i['type']== 'Country' or i['type']== 'NetworkGroup' or i['type']== 'Range' or i['type']== 'FQDN'):
            r=i['type']
    return r  


def CSV_policy(fmc1, acp_id, new_policy, database, object_db):

    bulk_rules = []
    linenumber=0
    number_of_bulk_rule = 0 
    known_categories=[]
    #MAX_BULK = 500
    MAX_BULK = 500

    current_section= database[0]['section']
    current_category = database[0]['category']

    print("Creating rules:") 
    print("Number of lines: ", len(database))
    print("-"*80)
    for rule in database:

        # Mandatory element to add  
        #rule['type']= "AccessRule"

        # Remove the number
        #rule.pop('number', None)

        # Warning: Category names are unique

        # Check Category:
        if (rule['category'] !='--Undefined--') and (rule['category'] !='') and (rule['category'] not in known_categories):
            known_categories.append(rule['category'])
            fmc1.createPolicyCat(acp_id, str(rule['category']), str(rule['section']), where_to=str(linenumber-1) )
            print(f"Creating New Category: {rule['category']}")

        rule1={
              "action": "ALLOW",
              "type": "AccessRule",
              "name": "Rule"+str(linenumber),
        }
        linenumber=linenumber+1

        rule1['action']= rule['action']
        rule1['enabled']= rule['enabled']
        rule1['name']= rule['name']


        #SECTION, CATEGORY HANDLING

        #rule1['section']= rule['section']
        #rule1['section']= 'mandatory'
        rule1['category'] =rule['category']

        #If a category is specified, a section cannot be specified.
        if rule['category'] == "--Undefined--":
                rule1['section'] = rule['section']

    
        if (current_category !=  rule['category']) or (current_section != rule['section']):
            print(">> Uploading the rules because of new section/category .. ") 
            # section=mandatory/default
            # If a category is specified, a section cannot be specified.
            if current_category != "--Undefined--":
                section_cat = "&category="+current_category
            else:    
                section_cat = "&section="+current_section.lower()

            r = fmc1.createRule(bulk_rules, acp_id, section_cat = section_cat )
            if  r != True:
                print(">>")
                exit() 
            number_of_bulk_rule = 0
            bulk_rules = []

            current_section = rule['section']
            current_category = rule['category']



        print(f"{linenumber} {current_section} {current_category} Rule name:{rule1['name']}")
         
        # Check the fields and copy to rule1
        if rule['sourceZones']:
             rule1['sourceZones'] =   {'objects':[{'name': element.strip(),'type': 'SecurityZone', "id":  find_id(object_db, element.strip(), 'SecurityZone')  } for element in rule['sourceZones'].split(';')]}     
            
        if rule['destinationZones']:    
            rule1['destinationZones']={'objects':[{'name': element.strip(),'type': 'SecurityZone', "id":  find_id(object_db, element.strip(), 'SecurityZone') } for element in rule['destinationZones'].split(';')]}
  
        if rule['sourceNetworks']:
            lits = []
            objs = [] 
            # !!! WARINING !!! Object Name is UNIQUE 
            for element in rule['sourceNetworks'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'Network')

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'Host')

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'NetworkGroup') 

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'Continent')

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'Country') 
                
                if object_id == '':
                    object_id = find_id(object_db, element_name, 'Range')

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'FQDN')    


                # lits
                if object_id =='':
                    if '/' in element_name:
                        lits.append({'type': 'Host', 'value':element_name })
                    else:
                        lits.append({'type': 'Network', 'value':element_name })         
                # objects     
                else:
                    obj_type= find_type(object_db, element_name)
                    objs.append( {'type': obj_type,  'id': object_id, 'name': element_name})

            if (lits != '') and (objs != ''):
                rule1['sourceNetworks']= {'literals': lits, 'objects': objs} 
            elif lits != '':
                rule1['sourceNetworks'] = {'literals': lits}
            elif objs != '':
                rule1['sourceNetworks'] = {'objects': objs} 

        if rule['destinationNetworks']:
            lits = []
            objs = [] 

            for element in rule['destinationNetworks'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'Network')

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'Host')

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'NetworkGroup')

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'Continent') 

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'Country') 

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'Range') 

                if object_id == '':
                    object_id = find_id(object_db, element_name, 'FQDN')                    

                # lits
                if object_id =='':
                    if '/' in element_name:
                        lits.append({'type': 'Host', 'value':element_name })
                    else:
                        lits.append({'type': 'Network', 'value':element_name })         
                # objects     
                else:
                    #objs.append( {'type': 'Network',  'id': object_id, 'name': element_name})
                    obj_type= find_type(object_db, element_name)
                    objs.append( {'type': obj_type,  'id': object_id, 'name': element_name})

            if (lits != '') and (objs != ''):
                rule1['destinationNetworks']= {'literals': lits, 'objects': objs} 
            elif lits != '':
                rule1['destinationNetworks'] = {'literals': lits}
            elif objs != '':
                rule1['destinationNetworks'] = {'objects': objs}


            # DEBUG
            # if linenumber == 10:
            #    print(f">> Original: {json.dumps(rule['destinationNetworks'], indent=4)}")
            #    print(f">> Processed: {json.dumps(rule1['destinationNetworks'], indent=4)}")    


        if rule['vlanTags']:  
            lits = []
            objs = [] 
            for element in rule['vlanTags'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'VlanTag')

                # lits
                if object_id =='':
                    if '-' in element_name:
                        starttag = element_name.split('-')[0]
                        endtag = element_name.split('-')[1]
                        lits.append({'type': 'VlanTagLiteral','startTag':starttag,'endTag':endtag })
                    else:    
                        lits.append({'type': 'VlanTagLiteral','startTag':element_name,'endTag':element_name })         
                # objects     
                else:
                    objs.append({'type': 'VlanTag','id': object_id,'name':element_name})

            if (lits != '') and (objs != ''):
                rule1['vlanTags']= {'literals': lits, 'objects': objs} 
            elif lits != '':
                rule1['vlanTags'] = {'literals': lits}
            elif objs != '':
                rule1['vlanTags'] = {'objects': objs}
                
        if rule['users']:                
            objs=[]
            for element in rule['users'].split(';'):
                element_name = element.strip()
                # domain\\user
                if "\\" in element_name:
                    domain_name=element_name.split("\\")[0]
                    user_name= element_name.split("\\")[1]
                    object_id_domain = find_id(object_db, domain_name, 'Realm')
                    object_id_user = find_id(object_db, user_name, 'RealmUser')
                    obj_type='RealmUser'
                    # domain\\group
                    if object_id_user=='':
                        object_id_user = find_id(object_db, user_name, 'RealmUserGroup')
                        obj_type='RealmUserGroup'

                    objs.append({"id":object_id_user,"type":obj_type,"name":domain_name, \
                    "realm":{"id":object_id_domain,"type":"Realm","name":user_name}})
            """
            if objs != '':
                rule1['users'] = {'objects': objs}  
            """

            """
            # Add Identity policy ID 
            # "users" require configured ID policy  
            object_id= find_id(object_db, 'ID_POLICY_ID', 'ID_POLICY_ID')   
            if object_id !="":
                rule1['id'] = object_id
            else:
                print("ERROR: Identity Policy ID not found!")
            """
            print("WARNING: Rule's 'users' field is not supported yet!")     
        

        if rule['applications']:
            """
            objs = [] 
            for element in rule['applications'].split(';'):
                if ':' in element:
                    key = element.split(':')[0]
                    if key == 'Categories':
                    objs.append({'categories'})   
            """        

            #rule1['applications']={'applications':[{'name':element.strip(), 'type': 'Application', 'id': find_id(object_db, element.strip(), 'Application') } for element in rule['applications'].split(';')]}
           
            objs = [] 
            filters= []
            for element in rule['applications'].split(';'):
                object_name = element.strip()
                object_id = find_id(object_db, object_name, 'Application')
                if object_id :
                    objs.append({ 'name' : object_name, "id": object_id,"type":"Application"})

                if object_id == "":
                    if "Risks:" in object_name:
                        object_name=object_name.split('Risks:')[1]
                        object_id = find_id(object_db, object_name, 'ApplicationRisk')
                        if object_id :
                            filters.append({'risks': [{ 'name' : object_name, "id": object_id,"type":"ApplicationRisk"}]})

                           
                    
                if object_id == "":
                    print(">> ERROR: app ID not found !", object_name) 
                    exit()
               
            if objs:
                rule1['applications'] = {'applications': objs}

            if filters:
                rule1['applications'] = {'inlineApplicationFilters': filters}

                    

        if rule['sourcePorts']:
            lits = []
            objs = [] 
            for element in rule['sourcePorts'].split(';'):
                element_name = element.strip()

                if   element_name == "TCP" :
                    lits.append({'type': 'PortLiteral', 'protocol': '6'})
                elif element_name == "UDP":    
                    lits.append({'type': 'PortLiteral', 'protocol': '17'})

                elif element_name == "ICMP":    
                    lits.append({'type': 'ICMPv4PortLiteral', 'protocol': '1'}) 

                elif ('ICMP:' in element_name):
                    lits.append({'type': 'ICMPv4PortLiteral', 'protocol': '1', 'icmpType': element_name.split(':')[1]})        

                #{'type': 'ICMPv4PortLiteral', 'protocol': '1', 'icmpType': '0'}
    
               

                elif ('TCP:' in element_name) or ('UDP:' in element_name):
                    #lits
                    lits.append({'type': 'PortLiteral', 'port': element_name.split(':')[1] ,'protocol': 6 if 'TCP' in element_name else 17 })
                elif str(element_name).isnumeric():
                    lits.append({'type': 'PortLiteral', 'protocol': element_name })    
                else:
                    # objects 
                    object_id = find_id(object_db, element_name, 'ProtocolPortObject')
                    if object_id != '':
                        objs.append({'type': 'ProtocolPortObject','id': object_id,'name':element_name})

                    if object_id == '':
                        object_id = find_id(object_db, element_name, 'ICMPV4Object')
                        if object_id != '':
                            objs.append({'type': 'ICMPV4Object','id': object_id,'name':element_name})   

                    if object_id == '':
                        object_id = find_id(object_db, element_name, 'PortObjectGroup')
                        if object_id != '':
                            objs.append({'type': 'ProtocolPortObject','id': object_id,'name':element_name})

                    if object_id == '':
                        print(">>> ERROR: category not found:",element,">>",element_name )    
                    objs.append({'type': 'ProtocolPortObject','id': object_id,'name':element_name})



            if (lits != '') and (objs != ''):
                rule1['sourcePorts']= {'literals': lits, 'objects': objs} 
            elif lits != '':
                rule1['sourcePorts'] = {'literals': lits}
            elif objs != '':
                rule1['sourcePorts'] = {'objects': objs}

        if rule['destinationPorts']:
            lits = []
            objs = [] 
            for element in rule['destinationPorts'].split(';'):
                element_name = element.strip()

                if   element_name == "TCP" :
                    lits.append({'type': 'PortLiteral', 'protocol': '6'})
                elif element_name == "UDP" :   
                    lits.append({'type': 'PortLiteral', 'protocol': '17'})

                elif element_name == "ICMP":    
                    lits.append({'type': 'ICMPv4PortLiteral', 'protocol': '1'}) 

                elif ('ICMP:' in element_name):
                    lits.append({'type': 'ICMPv4PortLiteral', 'protocol': '1', 'icmpType': element_name.split(':')[1]})   

                elif ('TCP:' in element_name) or ('UDP:' in element_name):
                    #lits
                    lits.append({'type': 'PortLiteral', 'port': element_name.split(':')[1] ,'protocol': 6 if 'TCP' in element_name else 17 })
                elif str(element_name).isnumeric():
                    lits.append({'type': 'PortLiteral', 'protocol': element_name })
                    
                else:
                 # objects 
                    object_id = find_id(object_db, element_name, 'ProtocolPortObject')
                    if object_id != '':
                        objs.append({'type': 'ProtocolPortObject','id': object_id,'name':element_name})

                    if object_id == '':
                        object_id = find_id(object_db, element_name, 'ICMPV4Object')
                        if object_id != '':
                            objs.append({'type': 'ICMPV4Object','id': object_id,'name':element_name})   

                    if object_id == '':
                        object_id = find_id(object_db, element_name, 'PortObjectGroup')
                        if object_id != '':
                            objs.append({'type': 'ProtocolPortObject','id': object_id,'name':element_name})

                    if object_id == '':
                        print(">>> WARNING: category not found:",element,">>",element_name )
                        objs.append({'type': 'ProtocolPortObject','id': object_id,'name':element_name})

            if (lits != '') and (objs != ''):
                rule1['destinationPorts']= {'literals': lits, 'objects': objs} 
            elif lits != '':
                rule1['destinationPorts'] = {'literals': lits}
            elif objs != '':
                rule1['destinationPorts'] = {'objects': objs}
    
        if rule['urls']:
            lits = []
            objs = [] 
            reputation_separator='['
            for element in rule['urls'].split(';'):
                element_name = element.strip()

                if ( reputation_separator not in element_name) and  (element_name != "Uncategorized"):
                    # lits
                    lits.append({'type': 'Url','url': element_name})
          
                else:
                    # objects 
                    if  reputation_separator in element_name:

                        real_name = element_name.split(reputation_separator)[0]

                        # CHECK THE REAL NAME WITH ;
                        # Object file contains the whole name of this Category
                        if real_name=='Conventions':
                            real_name = 'Conventions, Conferences and Trade Shows'

                        #print(">>",real_name)    
                        object_id = find_id(object_db, real_name, 'URLCategory')

                        if object_id=='':
                            print(f'Error: category not found: {element_name}')
                            exit()
                        objs.append({"category":{"name":real_name,"id":object_id,"type":"URLCategory"},"type":"UrlCategoryAndReputation","reputation":element_name.split(reputation_separator)[1][0: -1]})  
                            
                    else:
                        #Uncategorized Cat
                        object_id = find_id(object_db, element_name, 'URLCategory')
                        # >>> CHECK THE REAL NAME WITH ;
                        real_name = element_name
                        objs.append({ "category":{"name":"Uncategorized","id":object_id,"type":"URLCategory" },"type":"UrlCategoryAndReputation" })
                

            if (lits != '') and (objs != ''):
                rule1['urls']= {'literals': lits, 'urlCategoriesWithReputation': objs} 
            elif lits != '':
                rule1['urls'] = {'literals': lits}
            elif objs != '':
                rule1['urls'] = {'urlCategoriesWithReputation': objs} 

        # SRC SGT
        if rule['sourceSecurityGroupTags']:
            objs=[]
            for element in rule['sourceSecurityGroupTags'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'ISESecurityGroupTag')
                if object_id!='':
                    objs.append({"name":element_name,"id":object_id,"type":"ISESecurityGroupTag"})  
            if objs != '':
                rule1['sourceSecurityGroupTags'] = {'objects': objs}
                   
                
        # DST SGT
        if rule['destinationSecurityGroupTags']:
            objs=[]
            for element in rule['destinationSecurityGroupTags'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'ISESecurityGroupTag')
                if object_id!='':
                    objs.append({"name":element_name,"id":object_id,"type":"ISESecurityGroupTag"})  
            if objs != '':
                rule1['destinationSecurityGroupTags'] = {'objects': objs}
               
        # sourceDynamicObjects
        if rule['sourceDynamicObjects']:
            objs=[]
            for element in rule['sourceDynamicObjects'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'DynamicObject')
                if object_id!='':
                    objs.append({"name":element_name,"id":object_id,"type":"DynamicObject"})  
            if objs != '':
                rule1['sourceDynamicObjects'] = {'objects': objs}
        
        # destinationDynamicObjects
        if rule['destinationDynamicObjects']:
            objs=[]
            for element in rule['destinationDynamicObjects'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'DynamicObject')
                if object_id!='':
                    objs.append({"name":element_name,"id":object_id,"type":"DynamicObject"})  
            if objs != '':
                rule1['destinationDynamicObjects'] = {'objects': objs}   

        # networkAccessDeviceIPs
        if rule['networkAccessDeviceIPs']:
            objs=[]
            for element in rule['networkAccessDeviceIPs'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'Network')
                if object_id!='':
                    objs.append({"name":element_name,"id":object_id,"type":"Network"})  
            if objs != '':
                rule1['networkAccessDeviceIPs'] = {'objects': objs}    
      
        # endPointDeviceTypes
        if rule['endPointDeviceTypes']:
            objs=[]
            for element in rule['endPointDeviceTypes'].split(';'):
                element_name = element.strip()
                object_id = find_id(object_db, element_name, 'EndPointDeviceType')
                if object_id!='':
                    objs.append({"name":element_name,"id":object_id,"type":"EndPointDeviceType"})  
            if objs != '':
                rule1['endPointDeviceTypes'] = objs

        if rule['ipsPolicy']:
            object_id = find_id(object_db, rule['ipsPolicy'], 'IntrusionPolicy')     
            rule1['ipsPolicy'] = { 'name':  rule['ipsPolicy'], 'id': object_id,'type':'IntrusionPolicy'}

        if rule['variableSet']:
            object_id = find_id(object_db, rule['variableSet'], 'VariableSet')    
            rule1['variableSet'] = { 'name':  rule['variableSet'],'id': object_id,'type':'VariableSet'}
        
        if rule['filePolicy']:
            object_id = find_id(object_db, rule['filePolicy'], 'FilePolicy')
            rule1['filePolicy'] = {'name':  rule['filePolicy'],'id': object_id,'type':'FilePolicy'}
    
        if rule['sendEventsToFMC']:    
            rule1['sendEventsToFMC'] = rule['sendEventsToFMC']

        if rule['enableSyslog']:    
            rule1['enableSyslog'] = rule['enableSyslog']
            
        if rule['logBegin']:    
            rule1['logBegin'] = rule['logBegin']

        if rule['logEnd']:    
            rule1['logEnd'] = rule['logEnd']

        if rule['snmpConfig']:
            object_id = find_id(object_db, rule['snmpConfig'], 'SNMPAlert')
            rule1['snmpConfig'] = {'name':  rule['snmpConfig'],'id': object_id,'type':'SNMPAlert'}

    
        if rule['commentHistoryList']:

            # syntax: comment(user)[date]
            name_separator='('
            date_separator='['
            search_chars=')['    
            lits = []
            lits2 = []
            for element in rule['commentHistoryList'].split(';'):
                element_name = element.strip()
                """
                comment =element_name.split(name_separator)[0]
                username = element_name.split(name_separator)[1].split(date_separator)[0][:-1]
                date = element_name.split(name_separator)[1].split(date_separator)[1][:-1]
                """
                first_half = element_name.split(search_chars)[0]
                comment1 =first_half.split(name_separator)[0]
                comment = comment1.encode('utf_8','strict').decode('utf_8', 'strict')
                username=first_half.split(name_separator)[-1]
                date= element_name.split(search_chars)[1][:-1]


                lits.append({'user': {'name': username, 'type': 'User'}, 'comment': comment, 'date': date } )
                lits2.append(comment)

            #rule1['commentHistoryList'] = {'commentHistoryList' : lits }
            # Instead of commentHistoryList, we have to use newComments
            rule1["newComments"] = lits2 


        number_of_bulk_rule = number_of_bulk_rule+1
        bulk_rules.append(rule1)

        if number_of_bulk_rule ==  MAX_BULK or linenumber == len(database):
            print(">> Uploading the rules..")  

            # If a category is specified, a section cannot be specified.
            if current_category != "--Undefined--":
                section_cat = "&category="+current_category
            else:    
                section_cat = "&section="+current_section.lower()

            r = fmc1.createRule(bulk_rules, acp_id, section_cat= section_cat)
            if  r != True:
                print(">>")
                exit() 
            number_of_bulk_rule = 0
            bulk_rules = []
        # DEBUG
        #print (">>DEBUG Rule1:"+ json.dumps(rule1, indent=4))

    
def main():

    acp_id =""
    policy_filename= "_policy"
    object_filename= "_objects"

    object_db=[]

    hostname = fmc_config.host
    username = fmc_config.admin
    password = fmc_config.password

    print("FMC authentication for this FMC:", hostname)
    fmc1 = fmc(hostname, username, password)
       

    if (len(sys.argv) != 1):
        if (len(sys.argv) != 3) :
            print(f"python {sys.argv[0]} Domain_name AccessControlPolicy_name.csv")
            
    if (len(sys.argv) == 3):
       target_domain = sys.argv[1]
       target_csv_filename = sys.argv[2]
       cli_params = True
    else:
        print("Enter the domain name:") 
        target_domain = input()             
        print("Enter the policy filename with .csv:") 
        target_csv_filename = input()
    
    if target_csv_filename[-4:]!='.csv':
        print(f"Wrong filename",target_csv_filename[-4:] )
        exit()

    target_csv = target_csv_filename[:-4]
    print(f"Reading csv file:{target_csv_filename}")  
    print(f"Checking ACP policy:{target_csv}") 

    fmc1.tokenGeneration(domain=target_domain)
    acp_policies = fmc1.getPolicy()

    for policy in acp_policies['items']:
        if policy['name'] == target_csv:
           acp_id=policy['id'] 

    print(f"Reading policy file:{target_csv+policy_filename+'.json'}")
    policy_data=''
    try:
        f = open(target_csv+policy_filename+'.json')
        policy_data = json.load(f)
        f.close()

    except FileNotFoundError:
        print("File {} does not exist".format(target_csv+policy_filename+'.json')) 
           

    print(f"Reading object file:{target_csv+object_filename+'.csv'}")             
    with open(target_csv+object_filename + ".csv", 'r', newline='') as objectfile:
        reader = csv.DictReader(objectfile)
        for row in reader:
            object_db.append(row)       


    if acp_id !="":
        print(target_csv+" is a known policy, the script currently does not support it!") 
        print("Both Update and Delete methods are too slow." )
        print("Please rename your data files. " )
        
        exit()

    else:
        print(target_csv+" is a new policy!" )
        print("New policy CANNOT support User conditions! (FMC limitation)" )
        
        new_policy=True
        access_policy1 = {
         "type": "AccessPolicy",
         "name": target_csv,
         "defaultAction": {"action": "BLOCK"} }
        #print("New policy content:"+ json.dumps(access_policy1))
        acp_id=fmc1.createPolicy(data = access_policy1 )
        #print("Policy ID:", acp_id)

    database=[]

    
    with open(target_csv + ".csv", 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for line in reader:
            database.append(line)

    CSV_policy(fmc1, acp_id, new_policy, database, object_db)
    print("-"*80)
       

# Stand Alone execution
if __name__ == "__main__":
    main()