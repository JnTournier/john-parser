#!/bin/bash

#Add the option obfuscated password, for instance
# user : password -> user : pXXXXXXd

# This script is a parser to simplify the output of john the ripper
# When hashes are cracked, the --show option of john is not always comprehensible
# and not really usable to provide stat or to generate dictionnary
# So this script provides different format outputs that can ease the use of john results

# The following formats are available : user:password, only-password, unique-password, hashcat-format



# Usage function
function usage(){
    echo -e "Usage : $0 [options]"
    echo -e "\nOptions :"
    echo -e "\t-f <john-format>\tSet the format of the hash. Default : NT"
    echo -e "\t-c <file>\t\tThis file is the return of the --show option of john"
    echo -e "\t-i <hashdump>\t\tUse the hasdump file to get the result of the --show option and apply parsing on"
    echo -e "\t-o <output-file>\tExport the --show result in the output-file with the chossen format. Default : cleared-hashdump-nt.txt"
    echo -e "\t-s <format>\t\tProcess password cracked with different format, mainly to export them with different format output. Default : only-password-nt.txt"
    echo -e "\nAvailable output formats:"
    echo -e "\tup:\tuser/password separated with a : (user : password)"
    echo -e "\tp:\tonly password, display redundant passwords"
    echo -e "\tu:\tunique password"
    echo -e "\thc:\thashcat format for cracked passwords (hash:clear)"
    echo -e "It's possible to combine multiple output formats with -s up,p,u for example."
    exit 1
}

format=("up" "p" "u" "hc")
john_format="NT"
tmp_file="cleared-hashdump"
hashdump_file=""
input_file=""

all_john_format=("7z" "7z-opencl" "AFS" "agilekeychain" "agilekeychain-opencl" "aix-smd5" "aix-ssha1" "aix-ssha256" "aix-ssha512" "asa-md5" "bcrypt" "bcrypt-opencl" "bfegg" "Bitcoin" "blackberry-es10" "Blockchain" "blockchain-opencl" "bsdicrypt" "chap" "Citrix_NS10" "Clipperz" "cloudkeychain" "cq" "CRC32" "crypt" "dahua" "descrypt" "descrypt-opencl" "Django" "django-scrypt" "dmd5" "dmg" "dmg-opencl" "dominosec" "dragonfly3-32" "dragonfly3-64" "dragonfly4-32" "dragonfly4-64" "Drupal7" "dummy" "dynamic_n" "eCryptfs" "EFS" "eigrp" "EncFS" "encfs-opencl" "EPI" "EPiServer" "fde" "FormSpring" "Fortigate" "gost" "gpg" "gpg-opencl" "HAVAL-128-4" "HAVAL-256-3" "hdaa" "HMAC-MD5" "HMAC-SHA1" "HMAC-SHA224" "HMAC-SHA256" "HMAC-SHA384" "HMAC-SHA512" "hMailServer" "hsrp" "IKE" "ipb2" "KeePass" "keychain" "keychain-opencl" "keyring" "keyring-opencl" "keystore" "known_hosts" "krb4" "krb5" "krb5-18" "krb5pa-md5" "krb5pa-md5-opencl" "krb5pa-sha1" "krb5pa-sha1-opencl" "kwallet" "LastPass" "LM" "lotus5" "lotus5-opencl" "lotus85" "LUKS" "MD2" "md4-gen" "md5crypt" "md5crypt-opencl" "md5ns" "mdc2" "MediaWiki" "MongoDB" "Mozilla" "mscash" "mscash2" "mscash2-opencl" "MSCHAPv2" "mschapv2-naive" "mssql" "mssql05" "mssql12" "mysql" "mysql-sha1" "mysql-sha1-opencl" "mysqlna" "net-md5" "net-sha1" "nethalflm" "netlm" "netlmv2" "netntlm" "netntlm-naive" "netntlmv2" "nk" "nsldap" "NT" "nt-opencl" "nt2" "ntlmv2-opencl" "o5logon" "o5logon-opencl" "ODF" "ODF-AES-opencl" "ODF-opencl" "Office" "office2007-opencl" "office2010-opencl" "office2013-opencl" "oldoffice" "oldoffice-opencl" "OpenBSD-SoftRAID" "openssl-enc" "OpenVMS" "oracle" "oracle11" "osc" "Panama" "PBKDF2-HMAC-SHA1" "PBKDF2-HMAC-SHA1-opencl" "PBKDF2-HMAC-SHA256" "PBKDF2-HMAC-SHA256-opencl" "PBKDF2-HMAC-SHA512" "pbkdf2-hmac-sha512-opencl" "PDF" "PFX" "phpass" "phpass-opencl" "PHPS" "pix-md5" "PKZIP" "po" "postgres" "PST" "PuTTY" "pwsafe" "pwsafe-opencl" "RACF" "RAdmin" "RAKP" "RAKP-opencl" "rar" "rar-opencl" "RAR5" "RAR5-opencl" "Raw-Blake2" "Raw-Keccak" "Raw-Keccak-256" "Raw-MD4" "Raw-MD4-opencl" "Raw-MD5" "Raw-MD5-opencl" "Raw-MD5u" "Raw-SHA" "Raw-SHA1" "Raw-SHA1-Linkedin" "Raw-SHA1-ng" "Raw-SHA1-opencl" "Raw-SHA224" "Raw-SHA256" "Raw-SHA256-ng" "Raw-SHA256-opencl" "Raw-SHA384" "Raw-SHA512" "Raw-SHA512-ng" "Raw-SHA512-opencl" "ripemd-128" "ripemd-160" "rsvp" "Salted-SHA1" "sapb" "sapg" "scrypt" "sha1-gen" "sha1crypt" "sha1crypt-opencl" "sha256crypt" "sha256crypt-opencl" "sha512crypt" "sha512crypt-opencl" "Siemens-S7" "SIP" "skein-256" "skein-512" "skey" "Snefru-128" "Snefru-256" "SSH" "SSH-ng" "ssha-opencl" "SSHA512" "STRIP" "strip-opencl" "SunMD5" "sxc" "sxc-opencl" "Sybase-PROP" "sybasease" "tc_aes_xts" "tc_ripemd160" "tc_sha512" "tc_whirlpool" "tcp-md5" "Tiger" "tripcode" "VNC" "vtp" "wbb3" "whirlpool" "whirlpool0" "whirlpool1" "WoWSRP" "wpapsk" "wpapsk-opencl" "xsha" "xsha512" "XSHA512-opencl" "ZIP" "zip-opencl")

# This function check the correctness of a variable regarding the array used
# So this function take 2 args 
# $1 is the variable we want to check
# $@ is the array used to proess the check
function check_format(){
    local var="$1"
    shift
    local array=("$@")
    for f in "${array[@]}";
    do
	if [ $var == "$f" ]; then
	    #echo "Something happens here !!! But not today"
	    return 0 # true
	fi
    done
    return 1 # false
}

# Check options
while getopts ":f:c:i:o:s:h" opt; do
    case $opt in
	h)
	    usage
	    exit 1
	    ;;
	f)
	    if [ $(check_format $OPTARG "${all_john_format[@]}"; echo $?) -eq 0 ]; then
		echo "You chose the $OPTARG john format"
		john_format=$OPTARG
	    else
		echo "The choosen format ($OPTARG) is not supported with John the Ripper"
	    fi
	    ;;
	c)
	    if [ -f $OPTARG ]; then
		input_file=$OPTARG
	    else
		echo "This file $OPTARG does not exist"
		exit 1
	    fi
	    ;;
	i)
	    if [ -f $OPTARG ]; then
		hashdump_file=$OPTARG
	    else
		echo "This file $OPTARG does not exist"
		exit 1
	    fi
	    ;;
	o)
	    if [ -f $OPTARG ]; then
		tmp_file=$OPTARG
		
	    # If the file does not exist : there are 2 possibilities :
	    #     - The file does not exist, but i can create it
	    #     - The file does not exist, and the path is incorrect
	    else
		`touch $OPTARG 2> /dev/null`
	        if [[ -d $OPTARG || -f $OPTARG ]]; then
		    tmp_file=$OPTARG
		else
		    echo "The path $OPTARG does not exist !"
		    exit 1
		fi
	    fi
	    ;;
	s)
	    set -f # disable glob
	    IFS=',' # split on space characters
	    opt_array=($OPTARG) # use the split+glob operator
	    final_array=()
	    #Check the correctness of the argument format 
	    for arg in ${opt_array[@]};
	    do
		[ $(check_format $arg "${format[@]}"; echo $?) -eq 0 ] &&
		# If true then we push the value in the array
	        final_array+=($arg) ||
		# else we do nothing expect advice the user of the wrong option used
		echo "The following output format is not available : $arg"
	    done
	    if [ ${#final_array[@]} -eq 0 ]; then
		echo "Sorry you must use a correct format"
		usage
		exit 1
	    fi
	    ;;
	\?)
	    echo "Invalid option: -$OPTARG"
	    usage
	    ;;
	:)
	    echo "Missing arg after -$OPTARG"
	    usage
	    ;;
    esac
done

# Mutually exclusion option
# The user have to choose between the -i and -c options
if [[ $input_file && $hashdump_file ]]; then    echo "You must choose between -i or -c options, but not use both"
    usage
    exit 1
fi

if [[ ! $input_file && ! $hashdump_file ]]; then
    echo "You must choose one of the -i or -c options"
    usage
    exit 1
fi

if [ $input_file ]; then
    echo "You want to use the file containing the result of the --show option of john"
    cleared_hashdump=$( cat $input_file )
else
    echo "You want to use the hashdump file"
    cleared_hashdump=$( john --format=$john_format --show $hashdump_file | head -n -2 )
fi

# Process the creation of the output file
if [ ${#final_array[@]} -eq 1 ]; then
    output_file=$tmp_file
fi

for format in ${final_array[@]};
do
  if [ ! ${#final_array[@]} -eq 1 ]; then
    output_file="$tmp_file-$john_format-$format.txt"
  fi

  case $format in
      up)
	  ( echo $cleared_hashdump | tr ':' ';' | awk -F ';' '{print $1" : "$2}' | sed '/^\s*$/d' > $output_file )
	  ;;
      p)
	  ( echo $cleared_hashdump | cut -d: -f 2 | sed '/^\s*$/d' > $output_file )
	  ;;
      u)
	  ( echo $cleared_hashdump | cut -d: -f 2 | sed '/^\s*$/d' | sort -u > $output_file )
	  ;;
      hc)
	  ( echo $cleared_hashdump | tr ':' ';' | awk -F ';' '{print $5":"$2}' | sed '/^\s*$/d' > $output_file )
	  ;;
  esac
  echo "The output file $output_file has been created"
done
