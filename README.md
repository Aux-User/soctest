# soctest
This script allows the user to select a machine on a network and the type of attack to be performed on it. There are four attack options to choose from and both machine and attack choice may be specified by the user or randomly selected. The attack time, type and target are recorded.    

This script was written as part of my SOC Analyst module that I took for class.   
Below a short summary of what the script does while more details are available in the project documentation - [ProjDoc-SOC.pdf](https://github.com/Aux-User/soctest/blob/main/ProjDoc-SOC.pdf)    

The script executes as follows:
- Identify User machine IP and network range
- Scans network and lists possible targets for attack
- User is prompted to specify a target machine or opt for random selection
- User is prompted to select an attack to perform against target, or opt for random selection
  - Attack options are:
    - Denial of service (Hping3)
    - Brute force (Hydra)
    - Link-Local Multicast Name Resolution (Responder)
    - PsExec (Metasploit)
- Attack time, type and target are logged

**Addtional files in repository**    
pilotauth.txt and pilotroster.txt are the files containing login credentials used for the brute force attack recorded in the documentation.
