# FMC_CSV_Import_Export


This tool contains 4 python files: 

- fmc_config.py : FMC access parameters
                  Please update it with Your FMC's address and credentials!
                
- fmc_class.py  : FMC REST API requests

- fmc_import.py : This script will create the Policy and Object CSV files based on FMC Access Control Policy

- csv_export.py : This script will create NEW FMC ACP Policy based on Object and Policy CSV files 

#How to use:

1.  Export from FMC:

    python3 fmc_export.py Global BULK-ACP

    where Global is the domain name and BULK-ACP is the name of the ACP


2. You can modify the Policy ACP file and please **rename ALL of the 3 files** to the new ones, for example:

  BULK-ACP.csv         -> BULK-ACP**1**.csv 
 
  BULK-ACP_policy.csv  -> BULK-ACP**1**_policy.csv 
  
  BULK-ACP_policy.json -> BULK-ACP**1**_policy.json  
  
  
3.  CSV import to FMC:

    python3 csv_import.py Global BULK-ACP1.csv
    
    where Global is the domain name and BULK-ACP.csv is the name of the NEW ACP file.
    
    

