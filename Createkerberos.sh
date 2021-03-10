#!/bin/bash
master=$1
slave=$2
realm=$3
local_username=$4
akv_url=$5
private_key_name=$6
public_key_name=$7


function exit_script() # Testing Completed
{
        echo "ERROR - $1 !!!" |tee -a /var/log/hwx/krb_cluster_install_stderr.log;
        echo "Exiting the script execution"
        echo  "===================================================="
        exit 1
}
function warn_script() # Testing Completed
{
        echo "Warning - $1 !!!" | tee -a /var/log/hwx/krb_cluster_install_warn.log;
}
function add_log()
{
    echo `date "+%Y-%m-%d %H:%M:%S : $1"` | tee -a /var/log/hwx/krb_cluster_install.log;
}
function set_hostname() # pass relam as the parameter
{	
	add_log "Setting Hostname and /etc/hostname file"
	domain_lower=$(echo $1 |tr '[:upper:]' '[:lower:]')
	hn=$(echo $HOSTNAME |awk -F . '{print $1}'|tr '[:upper:]' '[:lower:]')

	if [ $(grep $domain_lower /etc/hostname|wc -l) -eq 0 ]; then
        	echo $hn.$domain_lower >/etc/hostname
        	hostname $hn.$domain_lower
		add_log "Hostname has been set"
	else 
		add_log "Hostname already set so ignoring"
		hostname $hn.$domain_lower
	fi
}

function get_akv_key() # 4 inputs 1) AKV URL 2) private KeyName  3) public Key name 4) Local User
{
curl -v  https://artifactory.vpc.npd.pvt.azu.westpac.com.au/artifactory/A009AA_DDEP_yum/jq -o /bin/jq
  chmod +x /bin/jq
  #Get the auth token
  export AKV_URL=$1
  #log "Using AKV: $2"
  GET_AT=$(curl -X GET \
       -H "Metadata: true" \
       "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net" \
       2>/dev/null  | jq '.access_token' | sed 's/\"//g')
  SECRET_PVT_VALS=()
  SECRET_PUB_VALS=()
  SECRET_PVT_VAL=""
  SECRET_PUB_VAL=""
  #Get the vlaues from key vault for the following secrets
  SECRETS=$2
  for SECRET in $SECRETS
  do
      SECRET_PVT_VAL=$(curl -k  -H  "Authorization : Bearer ${GET_AT}" -X GET \
      "${AKV_URL}/secrets/${SECRET}?api-version=2016-10-01" 2>/dev/null | \
      jq ".value" | sed 's/\"//g')
      SECRET_PVT_VALS+=(${SECRET_PVT_VAL})
  done

  SECRETS=$3
  for SECRET in $SECRETS
  do
      SECRET_PUB_VAL=$(curl -k  -H  "Authorization : Bearer ${GET_AT}" -X GET \
      "${AKV_URL}/secrets/${SECRET}?api-version=2016-10-01" 2>/dev/null | \
      jq ".value" | sed 's/\"//g')
      SECRET_PUB_VALS+=(${SECRET_PUB_VAL})
  done
  pvt=${SECRET_PVT_VALS[@]}
  pub=${SECRET_PUB_VALS[@]}
  if [[ -z $pvt || -z $pub ]] ; then 
	
     warn_script "Keyvalut returns null !!!!!! Check keyvault or arifactory URLL"
     warn_script "SSH key has not set !!!!!! Check keyvault or arifactory URLL"
  
  else   
  
        if [ ! -d "/home/$4/.ssh" ] ; then
        mkdir /home/$4/.ssh
        chown $4 /home/$4/.ssh
        chmod 700 /home/$4/.ssh
        fi
        if [ ! -d "/root/.ssh" ] ; then
        mkdir /root/.ssh
        chmod 700 /root/.ssh
        fi
  	add_log "Adding SSH keys to the root and authorzied keys for $4"
  	echo -en ${SECRET_PUB_VALS[@]}>/home/$4/.ssh/authorized_keys
  	chmod 600 /home/$4/.ssh/authorized_keys
  	chown $4  /home/$4/.ssh/authorized_keys
  	echo -en ${SECRET_PVT_VALS[@]}>/root/.ssh/id_rsa
  	echo -en ${SECRET_PUB_VALS[@]}>/root/.ssh/id_rsa.pub
  	chmod 600 /root/.ssh/id_rsa.pub /root/.ssh/id_rsa 
   fi	
}
function add_slave_kdc () # one input 1) second kdc FQDN
{
	date_log=$(date +%y%m%d%H%M%S)
        if [[ -f "/etc/krb5.conf" ]] ; then 
            cp /etc/krb5.conf /etc/krb5.conf_$date_log
	fi	
        add_log "adding second KDC"
	if [ $(grep -c $1 /etc/krb5.conf) -eq 0 ] ; then
        	count=$(grep -n 'realms' /etc/krb5.conf |awk -F: '{print$1}')
        	count=`expr $count + 2`
        	sed -i "$count"a" kdc =  $1" /etc/krb5.conf
        	add_log "second KDC added"
	else 
		add_log " Entry already exists"
	fi



}

function add_principal() # 2 input 1) Master FQDN 2 ) SLAVE FQDN
{
	add_log " Adding Host principals for $1 and $2"
	kadmin.local -q "addprinc -randkey host/$1"
	kadmin.local -q "addprinc -randkey host/$2"
	kadmin.local -q "ktadd  host/$1"
	kadmin.local -q "ktadd  host/$2"
	add_log " Added Host principals for $1 and $2"

}


function create_cron() # input 1) Slave FQDN
{
	add_log="creating cron file /etc/krb_dump"
echo "#!/bin/sh
kdclist=SLAVE-HOST
/sbin/kdb5_util dump /var/spool/slave_data_trans
for kdc in \$kdclist
do
    /sbin/kprop -f /var/spool/slave_data_trans \$kdc
done" >/etc/krb_dump

	kdb5_util dump /tmp/datatrans_slave
	sed -i "s/SLAVE-HOST/$1/g" /etc/krb_dump
	chmod 775 /etc/krb_dump

	if [ $(crontab -l |grep "/etc/krb_dump" |wc  -l) -eq 0 ]; then

        	crontab -l | { cat; echo "*/2 * * * * /etc/krb_dump"; } | crontab

	fi

        if [[ -f "/etc/krb_dump" ]]; then
		add_log "cron created successfully"
	fi 
}

function pack_file()
{	
       add_log "packing files for slave"
       tar cvzf /tmp/krb_to_slave.tar.gz "/etc/krb5.conf" "/etc/krb5.keytab" "/var/kerberos/krb5kdc/kdc.conf" "/var/kerberos/krb5kdc/kadm5.acl"
       chmod 775 /tmp/krb_to_slave.tar.gz
       if [[ -f "/tmp/krb_to_slave.tar.gz" ]]; then
             add_log "file /tmp/krb_to_slave.tar.gz  created successfully"
       else 
             warn_script " Some error occured while creating /tmp/krb_to_slave.tar.gz"   
       fi
}

###### Script Starts here######
master_server=$(echo $master |tr '[:upper:]' '[:lower:]')
slave_server=$(echo $slave |tr '[:upper:]' '[:lower:]')


if [[ -z $master_server || -z $slave_server || -z $realm || -z $local_username || -z $akv_url ]] ; then 

	exit_script "Parameter Missing Require  MasterFQDN SlaveFQDN Realm LocalUserName AKV_URL"
fi 


set_hostname $realm
get_akv_key  $akv_url $private_key_name $public_key_name $local_username
add_slave_kdc $slave_server 
add_principal $master_server $slave_server
create_cron $slave_server
pack_file
