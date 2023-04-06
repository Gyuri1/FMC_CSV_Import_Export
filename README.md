# FMC_CSV_Import_Export


This tool can create a CSV file from Cisco FMC Access Control Policy (ACP)  
and can import back the modified ACP into FMC. It contains 4 python files: 

- fmc_config.py : FMC access parameters  
   **Please update it with Your FMC's address and credentials!**
                
- fmc_class.py  : FMC REST API requests

- fmc_import.py : This script will create the Policy and Object CSV files based on FMC Access Control Policy

- csv_export.py : This script will create NEW FMC ACP Policy based on Object and Policy CSV files 

# How to install:

  Copy these 4 files into a working directory and make sure `requests` is an installed python library:
  
  `pip install requests`

# How to use:

1.  Export from FMC:

    `python fmc_export.py Global BULK-ACP`

    where Global is the domain name and BULK-ACP is the name of the ACP.

    This is the syntax of a non-Global domain, like DC:  `Global\DC`.


2. You can modify the Policy ACP CSV file using the **known objects** and please **rename ALL of the 3 files** to the new ones, for example:

   > BULK-ACP.csv         -> BULK-ACP**1**.csv 
 
   > BULK-ACP_policy.json  -> BULK-ACP**1**_policy.json
  
   > BULK-ACP_objects.csv -> BULK-ACP**1**_objects.csv 
  
  
3.  CSV import to FMC:

    `python csv_import.py Global BULK-ACP1.csv`
    
    where Global is the domain name and BULK-ACP.csv is the name of the NEW ACP file.
    
    

# WARNING: 

Tool currently does NOT support users field. This is an FMC Policy Creation limit.

Please review the NEW policy before deploying it!
    
Use it at your own risk! THIS IS DEMO CODE - NO WARRANTY OR SUPPORT IS IMPLIED OR PROVIDED!
PRs are welcome! 
    
It was tested with FMC 7.2 and 7.3 versions as well, but older releases were not tested. 



    

