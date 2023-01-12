# FMC_CSV_Import_Export


This tool can create a CSV file from Cisco FMC Access Control Policy (ACP) and can import back into FMC. 
It contains 4 python files: 

- fmc_config.py : FMC access parameters  
   **Please update it with Your FMC's address and credentials!**
                
- fmc_class.py  : FMC REST API requests

- fmc_import.py : This script will create the Policy and Object CSV files based on FMC Access Control Policy

- csv_export.py : This script will create NEW FMC ACP Policy based on Object and Policy CSV files 

# How to install:

  Copy these 4 files into a working directory and make sure requests is an installed python library:
  
  `pip install requests`

# How to use:

1.  Export from FMC:

    `python3 fmc_export.py Global BULK-ACP`

    where Global is the domain name and BULK-ACP is the name of the ACP


2. You can modify the Policy ACP file using the **known objects** and please **rename ALL of the 3 files** to the new ones, for example:

   > BULK-ACP.csv         -> BULK-ACP**1**.csv 
 
   > BULK-ACP_policy.csv  -> BULK-ACP**1**_policy.csv 
  
   > BULK-ACP_policy.json -> BULK-ACP**1**_policy.json  
  
  
3.  CSV import to FMC:

    `python3 csv_import.py Global BULK-ACP1.csv`
    
    where Global is the domain name and BULK-ACP.csv is the name of the NEW ACP file.
    
    

# WARNING: 

    Tool currently does NOT support users field. This is an FMC Policy Creation limit.
 
    Please review the NEW policy before you deploy it!
    
    Use it at your own risk!  



    

