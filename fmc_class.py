# fmc_class

import sys
import requests
import json
import csv

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Global Variable

globalRules = {}

#
#  fmc
#

class fmc (object):
    """Class to define the FMC.
    Attributes
    Host: FMC hostname (FQDN OR IP)
    Username: FMC Username for API user
    Password: FMC Password for API user
    """

    def __init__(self, host, username, password):
        """Return FMC object whose attributes are host, username and password. 
        init
        """
        self.host = host
        self.username = username
        self.password = password
        self.headers = {'Content-Type': 'application/json'}
        self.uuid = ""
        self.domains = {}
        self.acl_query_limit ='500'

    # common function    
    def tokenGeneration(self, domain):
        """Generate token."""
        path = "/api/fmc_platform/v1/auth/generatetoken"
        server = "https://"+self.host
        url = server + path
        try:
            r = requests.post(url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=False)
            auth_headers = r.headers
            token = auth_headers.get('X-auth-access-token', default=None)
            self.domains = auth_headers.get('DOMAINS', default=None)
            self.domains = json.loads("{\"domains\":" + self.domains + "}")

            
            for item in self.domains["domains"]:
                if item["name"] == domain:
                    self.uuid = item["uuid"]
            """        
                else:
                    print("ERROR:UUID NOT FOUND FOR SPECIFIED DOMAIN")
            """        
            if token is None:
                    print("No Token found, I'll be back terminating....")
                    sys.exit()
        
        except Exception as err:
            print ("Error in generating token --> " + str(err))
            sys.exit()
        self.headers['X-auth-access-token'] = token

    # export funtion    
    def get_accesspolicies(self):
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies"
        server = "https://"+self.host
        url = server + path
        more_items = []
        try:
            session = requests.Session()
            r = session.get(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            final_response=json_response

            if json_response['paging']:
                num_pages=json_response['paging']['pages']
                print('Policy Pages:', num_pages)
                for page in range(2, num_pages + 1):
                    url=json_response['paging']['next'][0]
                    json_response = session.get(url, headers=self.headers, verify=False).json()
                    more_items.extend(json_response["items"])
                final_response['items']+=more_items 

            return final_response
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err))
        finally:
            if r:
                r.close() 

    # export funtion 
    def get_acp_rules(self, policy_id):
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/"+policy_id+"/accessrules?limit="+self.acl_query_limit+"&expanded=true"
        server = "https://"+self.host
        url = server + path
        more_items = []
        try:
            session = requests.Session()
            r = session.get(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
           
            final_response=json_response
            #final_list= json_response['items']
         
            if json_response['paging']:
                num_pages=json_response['paging']['pages']
                print('Rule Pages:', num_pages)
                for page in range(2, num_pages + 1):
                    url=json_response['paging']['next'][0]
                    resp=session.get(url, headers=self.headers, verify=False)
                    print("Response status code:", resp.status_code)
                    json_response = resp.json()
                    more_items.extend(json_response["items"])

                final_response['items']+=more_items 

            return final_response
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err))
        finally:
            if r:
                r.close()

    # export funtion 
    def get_acp_rule(self, policy_id, rule_id):
            path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/"+policy_id+"/accessrules/"+rule_id
            server = "https://"+self.host
            url = server + path
            try:
                r = requests.get(url, headers=self.headers, verify=False)
                status_code = r.status_code
                resp = r.text
                json_response = json.loads(resp)

                return json_response
            except requests.exceptions.HTTPError as err:
                print ("Error in connection --> " + str(err))
            finally:
                if r:
                    r.close()              

    # import funtions                 
    def createPolicy(self, data):
        """Create access policy with data given."""
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies"
        server = "https://"+self.host
        url = server + path
        try:
            r = requests.post(url, data=json.dumps(data), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)

            if status_code != 201 and status_code != 202:
                r.raise_for_status()
                print("Error occured in POST -->" + resp)
            return json_response["id"]
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err) + "\nResponse:"+ resp + "\nData:"+ json.dumps(data))
        finally:
            if r:
                r.close()

    def renamePolicy(self, acp_id, target_csv):
        """Rename access policy """
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/"+ acp_id
        server = "https://"+self.host
        url = server + path
        try:
            r = requests.get(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response1 = json.loads(resp)

            json_response1['name'] = target_csv 
            json_response1.pop('metadata', None)
            json_response1.pop('links', None)
            json_response1.pop('rules', None)
            data={ 'name' : target_csv}

            # PUT     
            r = requests.put(url, data=json.dumps(json_response1), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)

            if status_code != 200:
                r.raise_for_status()
                print("error occured in PUT -->" + resp)
            return json_response["id"]
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err) + "\nResponse:"+ resp + "\nData:"+ json.dumps(json_response1))
        finally:
            if r:
                r.close()

    def deletePolicy(self, acp_id):
        """Delete access policy"""
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/"+ acp_id
        server = "https://"+self.host
        url = server + path
        try:
            r = requests.delete(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            if status_code != 200 :
                r.raise_for_status()
                print("error occured in Delete -->" + resp)
            return json_response["id"]
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err) + "\nResponse:"+ resp + "\nData:"+ json.dumps(data))
        finally:
            if r:
                r.close()


    def deleteRule(self, acp_id, rule_id):
        """Delete access rule"""
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/"+ acp_id+"/accessrules/"+rule_id
        server = "https://"+self.host
        url = server + path
        try:
            r = requests.delete(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            if status_code != 200 :
                r.raise_for_status()
                print("error occured in Delete -->" + resp)
            return json_response["id"]
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err) + "\nResponse:"+ resp + "\nData:"+ json.dumps(data))
        finally:
            if r:
                r.close()



    # import function
    def createRule(self, data, policy_id):
        """Create rule with data given."""
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/" + policy_id + "/accessrules?bulk=true"
        server = "https://"+self.host
        url = server + path
        try:
            r = requests.post(url, data=json.dumps(data), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            #print("status code is: " + str(status_code))
            if status_code != 201 and status_code != 202:
                r.raise_for_status()
                print ("error occured in POST -->" + resp)
            return True
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err) + resp + "\nData:"+ json.dumps(data))
        finally:
            if r:
                r.close()

    def createRuleNonBulk(self, data, policy_id):
        """Create rule with data given."""
        #print("Calling: /api/fmc_config/v1/domain/" , self.uuid , "/policy/accesspolicies/" , policy_id , "/accessrules")
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/" + policy_id + "/accessrules"
        server = "https://" + self.host
        url = server + path
        try:
            r = requests.post(url, data=json.dumps(data), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            if status_code != 201 and status_code != 202:
                r.raise_for_status()
                print("error occured in POST -->" + resp)
            return True
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err) + resp + "\nData:"+ json.dumps(data))
     
        finally:
            if r:
                r.close()

    # import function
    def createPolicyCat(self, policy_id, category, section):
        """ Create Category """
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/" + policy_id + "/categories?section="+section
        data={ "type": "Category","name": category}
        server = "https://" + self.host
        url = server + path
        try:
            r = requests.post(url, data=json.dumps(data), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            if status_code != 201 and status_code != 202:
                r.raise_for_status()
                print("error occured in POST -->" + resp)
            return True
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err) + resp + "\nData:"+ json.dumps(data))
     
        finally:
            if r:
                r.close()            
            

    def updateRule(self, data, policy_id):
        """Update rule with data given."""   
        short_path = "/api/fmc_config/v1/domain/"+self.uuid+"/policy/accesspolicies/"+ policy_id+"/accessrules"
        # If a category is specified, a section cannot be specified.
        if category=='--Undefined--':
            cat_part=''
        else:                                                                                                                   
            cat_part="&category="+str(category)
        if section=='':
            section_part=''
            print("Error: section is empty!")
        elif 'default' in section.lower() :                                                                                                                   
            section_part="&section=default"
        else:
            section_part="&section=mandatory"
        if cat_part!='':
              section_part=''  
        path = short_path+cat_part+section_part

        server = "https://" + self.host
        url = server + path
        try:
            r = requests.put(url, data=json.dumps(data), headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            if status_code != 201 and status_code != 202:
                r.raise_for_status()
                print("error occured in POST -->" + resp)
            return True
        except requests.exceptions.HTTPError as err:
            print ("Error in connection --> " + str(err) + resp + "\nData:"+ json.dumps(data))
     
        finally:
            if r:
                r.close()


    # import funtion
    def getPolicy(self):
        """Get access policy with data given."""
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies"
        server = "https://" + self.host
        url = server + path
        try:
            r = requests.get(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            #print("status code is: " + str(status_code))
            if status_code != 200 and status_code != 201 and status_code != 202:
                r.raise_for_status()
                print("error occured in POST -->" + resp)
            return json_response
            #return resp
        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
        finally:
            if r:
                r.close()

    # export funtion            
    def getPolicy_details(self, policy_id):
        """Get access policy with data given."""
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/"+ policy_id
        server = "https://" + self.host
        url = server + path
        try:
            r = requests.get(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            #print("status code is: " + str(status_code))
            if status_code != 200 and status_code != 201 and status_code != 202:
                r.raise_for_status()
                print("error occured in POST -->" + resp)
            return json_response
            #return resp
        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
        finally:
            if r:
                r.close()            


    #/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{containerUUID}/categories
    def getCategories(self, containerUUID):
        """Get access policy with data given."""
        path = "/api/fmc_config/v1/domain/" + self.uuid + "/policy/accesspolicies/"+containerUUID+"/categories"
        server = "https://" + self.host
        url = server + path
        try:
            r = requests.get(url, headers=self.headers, verify=False)
            status_code = r.status_code
            resp = r.text
            json_response = json.loads(resp)
            #print("status code is: " + str(status_code))
            if status_code != 200 and status_code != 201 and status_code != 202:
                r.raise_for_status()
                print("error occured in POST -->" + resp)
            return json_response
            #return resp
        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
        finally:
            if r:
                r.close()

  