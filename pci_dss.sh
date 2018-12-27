#!/bin/bash

#
#
# Description: set PCI DSS parameters for RHEL 5.x / 6.x / 7.4 (only)
#

# rel_host - hostname for relayhost postfix
# rel_ip   - ip for relayhost postfix
# dom_ip   - domain ip for resolv
# dom_fqdn - FQDN domain name

rel_host="example.mail.com"
rel_ip="1.1.1.1"
dom_fqdn="example.com"
dom_ip="2.2.2.2"

##


UNIXTIME=`date +%s`

if [ "X`grep '5\.' /etc/redhat-release`" != "X" ]; then
	VERSION=5
elif [ "X`grep '6\.' /etc/redhat-release`" != "X" ]; then
	VERSION=6
elif [ "X`grep '7\.4' /etc/redhat-release`" != "X" ]; then
	VERSION=74
else
	echo "Not supported OS version! Check content of /etc/redhat-release file."
	exit
fi

SERVICES="anacron
apmd
atd
autofs
avahi-daemon
avahi-dnsconfd
bluetooth
capi
conman
cups
dnsmasq
dund
firstboot
gpm
hidd
hplip
ipmi
irda
irqbalance
isdn
kdump
kudzu
mcstrans
mdmonitor
mdmpd
multipathd
netconsole
netfs
netplugd
nscd
pand
pcscd
portmap
psacct
rawdevices
rdisc
readahead_early
readahead_later
restorecond
rhnsd
saslauthd
setroubleshoot
vncserver
wdaemon
winbind
wpa_supplicant
xinetd
ypbind
yum-updatesd
chargen-dgram
chargen-stream
daytime-dgram
daytime-stream
discard-dgram
discard-stream
echo-dgram
echo-stream
eklogin
ekrb5-telnet
gssftp
klogin
krb5-telnet
kshell
rmcp
rsync
tcpmux-server
tftp
time-dgram
time-stream"

# =====================================================================
# password policy

# for deffaults parameters

echo "Set password policy in /etc/login.defs"

cp -p /etc/login.defs /etc/login.defs.old$UNIXTIME

ed /etc/login.defs << END
/^PASS_MIN_DAYS/d
i
PASS_MIN_DAYS	7
.
w
q
END

if [ "X`diff /etc/login.defs /etc/login.defs.old$UNIXTIME`" = "X" ]; then
	rm -f /etc/login.defs.old$UNIXTIME
fi


echo "Set password policy in /etc/pam.d/system-auth"

cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.old$UNIXTIME

if [ "$VERSION" = "5" ]; then
	cat >/etc/pam.d/system-auth <<END
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        required      pam_tally2.so deny=6 onerr=fail unlock_time=1800
auth        required      pam_access.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so

password    requisite     pam_cracklib.so minlen=7 lcredit=-1 dcredit=-1 try_first_pass retry=3
password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok remember=4
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
END

elif [ "$VERSION" = "6" ]; then
	cat >/etc/pam.d/system-auth <<END
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.

auth        required      pam_env.so
auth        required      pam_tally2.so deny=6 onerr=fail unlock_time=1800
auth        required      pam_access.so
auth        sufficient    pam_fprintd.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so

password    requisite     pam_cracklib.so minlen=7 lcredit=-1 dcredit=-1 try_first_pass retry=3
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=4
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
END

	cp -p /etc/pam.d/sshd /etc/pam.d/sshd.old$UNIXTIME
	cat >/etc/pam.d/sshd <<END
#%PAM-1.0
auth       required     pam_sepermit.so
auth       required     pam_tally2.so deny=6 onerr=fail unlock_time=1800
auth       include      password-auth
account    required     pam_nologin.so
account    required     pam_tally2.so
account    include      password-auth
password   include      password-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
session    required     pam_selinux.so open env_params
session    optional     pam_keyinit.so force revoke
session    include      password-auth
END
	if [ "X`diff /etc/pam.d/sshd /etc/pam.d/sshd.old$UNIXTIME`" = "X" ]; then
		rm -f /etc/pam.d/sshd.old$UNIXTIME
	fi
fi

if [ "X`diff /etc/pam.d/system-auth /etc/pam.d/system-auth.old$UNIXTIME`" = "X" ]; then
	rm -f /etc/pam.d/system-auth.old$UNIXTIME
fi

if [ "$VERSION" = "74" ]; then

	echo "Set password policy in /etc/pam.d/system-auth-ac for pwquality module"

	cp -p /etc/pam.d/system-auth-ac /etc/pam.d/system-auth-ac.old$UNIXTIME
	cp -p /etc/security/pwquality.conf /etc/security/pwquality.conf.old$UNIXTIME

	pw_file=/etc/security/pwquality.conf
	mln_s="minlen = 7"
	mln_sd="# minlen = 9"
	lcr_s="lcredit = -1"
	lcr_sd="# lcredit = 1"
	dcr_s="dcredit = -1"
	dcr_sd="# dcredit = 1"
	rtr="retry=3"
	rmbrsa="pam_unix.so sha512 shadow nullok"
	rmbr="remember=4"

	# uncommnet line minlen and replace deafult

	grep -q "$mln_sd" "$pw_file"
		if [[ $? -eq $SUCCESS ]]; then
			sed -i -e "s/$mln_sd/$mln_s/" $pw_file
		fi

	# get curren and set required minlen

	grep -q "$mln_s" "$pw_file"
        if [[ $? -ne $SUCCESS ]]; then
			c_mln=`grep -P minlen $pw_file`
			sed -i -e "s/$c_mln/$mln_s/" $pw_file
		fi

	# uncommnet line lcredit and replace deafult

	grep -q "$lcr_sd" "$pw_file"
        if [[ $? -eq $SUCCESS ]]; then
            sed -i -e "s/$lcr_sd/$lcr_s/" $pw_file
        fi

    # get curren and set required lcredit

    grep -q "$lcr_s" "$pw_file"
    	if [[ $? -ne $SUCCESS ]]; then
            c_lcr=`grep -P lcredit $pw_file`
            sed -i -e "s/$c_lcr/$lcr_s/" $pw_file
    	fi

	# uncomment line dcredit and replace deafult

	grep -q "$dcr_sd" "$pw_file"
        if [[ $? -eq $SUCCESS ]]; then
       	    sed -i -e "s/$dcr_sd/$dcr_s/" $pw_file
        fi

        # get current and set required dcredit

    grep -q "$dcr_s" "$pw_file"
        if [[ $? -ne $SUCCESS ]]; then
            c_dcr=`grep -P dcredit $pw_file`
            sed -i -e "s/$c_dcr/$dcr_s/" $pw_file
        fi

	# replace parameters on /etc/pam.d/system-auth-sc

	echo "Set additional config on /etc/pam.d/system-auth-ac"

	saac_file=/etc/pam.d/system-auth-ac

	grep -q $rtr $saac_file
	if [[ $? -ne $SUCCESS ]]; then
		sed -i -e "s/retry=[0-9]*/$rtr/" $saac_file
	fi

	grep -q remeber $saac_file
	if [[ $? -ne $SUCCESS ]]; then
		sed -i -e "/$rmbrsa/ s/$/ $rmbr/" $saac_file
	fi

	grep -q $rmbr $saac_file
	if [[ $? -ne $SUCCESS ]]; then
		sed -i -e "s/remeber=[0-9]*/$rmbr/" $saac_file
	fi
fi


# sshd pam settings

if [ "$VERSION" = "74" ]; then

	cp -p /etc/pam.d/sshd /etc/pam.d/sshd.old$UNIXTIME

	pam_sshd=/etc/pam.d/sshd
	dn="deny=6"
	on="onerr=fail"
	ut="unlock_time=1800"

	grep -q pam_tally2.so $pam_sshd

	if [[ $? -ne $SUCCESS ]]; then
    	    sed -i -e '/auth[[:space:]]*required[[:space:]]*pam_sepermit.so/a auth       required     pam_tally2.so deny=6 onerr=fail unlock_time=1800' $pam_sshd
	fi

	grep -q $dn $pam_sshd
	if [[ $? -ne $SUCCESS ]]; then
        sed -i -e "s/deny=[0-9]*/$dn/" $pam_sshd
	fi

	grep -q $on $pam_sshd
	if [[ $? -ne $SUCCESS ]]; then
        sed -i -e "s/onerr=[a-z]*/$on/" $pam_sshd
	fi

	grep -q $ut $pam_sshd
	if [[ $? -ne $SUCCESS ]]; then
        sed -i -e "s/unlock_time=[0-9]*/$ut/" $pam_sshd
	fi
fi


# for exists users parameters

echo
echo "Set min days for exists users"

for user in `grep ':\\$' /etc/shadow | cut -d: -f1`; do
	chage -m 7 $user
done


# =====================================================================
# chkpass script

echo
echo "Create /opt/chkpassscript/chkpass_rhel.sh script"

[ ! -d /opt/chkpassscript ] && mkdir /opt/chkpassscript

cat <<ENDSCRIPT >/opt/chkpassscript/chkpass_rhel.sh
#!/bin/bash

h=\`hostname\`
expd="14"
mage="76"
email='lexy@akbars.ru'

function chk_pass {

    # currnet in /etc/shadow days
    dy=\`grep -w "^\$var" /etc/shadow | cut -d: -f3\`

    # current in system days
    cdy=\`perl -e 'print int(time/(86400))'\`

    # pass age
    agd=\`expr \$cdy - \$dy\`

    # age user pass and maxage in config,
    # use this only set maxage in /etc/shadow
    # mage=\`grep -w "^\$var" /etc/shadow | cut -d: -f5\`

    # pass expire days
    cpst=\`expr \$mage - \$agd\`

    # last change
    lch=\`perl -e 'print scalar localtime('\$dy' * 86400);'\`

    # check expire user password
    if [ "\$cpst" -le "\$expd" ];then
        echo "Password for user '\$var' expires in \$cpst days on server '\$h'. Please change the password for this user. Thank you." | mail -s "\$h. expire password user '\$var'" \$email
        echo "Password for user '\$var' expires in \$cpst days on server '\$h'. Please change the password for this user. Thank you."
    fi
}

for var in \`grep ':\\\\\$' /etc/shadow | cut -d: -f1\`
do
    chk_pass
done
ENDSCRIPT

chmod ug+x /opt/chkpassscript/chkpass_rhel.sh



# =====================================================================
# don't permit root login

# Configure SSH for RHEL 5.x / 6.x

if [ "$VERSION" = "5" ] || [ "$VERSION" = "6" ]; then

echo
echo "Set PermitRoot in /etc/ssh/sshd_config"

cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.old$UNIXTIME

cat /etc/ssh/sshd_config.old$UNIXTIME | grep -v '^PermitRootLogin' >/etc/ssh/sshd_config
echo >>/etc/ssh/sshd_config
echo "PermitRootLogin no" >>/etc/ssh/sshd_config

service sshd restart

fi

# for RHEL 7.4

if [ "$VERSION" = "74" ]; then

	cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.old$UNIXTIME

	fl_sshd="/etc/ssh/sshd_config"

	grep -q '^PermitRootLogin' $fl_sshd
	if [[ $? -ne $SUCCESS ]]; then
		sed -i -e "s/#PermitRootLogin[[:space:]]*[a-z]*/PermitRootLogin no/" $fl_sshd
	fi

	grep -q '^PermitRootLogin[[:space:]]*yes' $fl_sshd
	if [[ $? -eq $SUCCESS ]]; then
		sed -i -e "s/PermitRootLogin[[:space:]]*[a-z]*/PermitRootLogin no/" $fl_sshd
	fi

	/usr/bin/systemctl restart sshd.service

fi

# Create ftpusers file

echo
echo "Create /etc/ftpusers"

cat <<END_FTP >/etc/ftpusers
root
daemon
bin
sys
adm
uucp
guest
lpd
invscout
imnadm
ipsec
nwroot
nwuser
nwprint
nwldap
ldap
nuucp
netinst
END_FTP

echo
echo "Clear /etc/securetty"

echo >/etc/securetty


# =====================================================================
# Disable not usable services

# For RHEL 5.x/6.x

if [ "$VERSION" = "5" ] || [ "$VERSION" = "6" ]; then

	echo
	echo "Disable services:"
	echo

	[ ! -d /opt/sysscript ] && mkdir /opt/sysscript

	chkconfig --list >/opt/sysscript/oldstate.$UNIXTIME

	for s in $SERVICES; do
    	    echo "service $s"
        	chkconfig $s off
        	service $s stop
		echo
	done
fi

# for RHEL 7.4

if [ "$VERSION" = "74" ]; then

SERVICES_CHCK="daytime-stream
discard-dgram
discard-stream
echo-dgram
echo-stream
time-dgram
time-stream
tftp"

SERVICES_SYSD="xinetd
avahi-daemon
cups
dhcpd
slapd
nfs
rpcbind
named
vsftpd
httpd
dovecot
smb
squid
snmpd
ypserv
rsh.socket
rlogin.socket
rexec.socket
telnet.socket
tftp.socket
rsyncd
ntalk
atd.service
wpa_supplicant.service
systemd-firstboot.service
avahi-dnsconfd.service
irqbalance.service
kdump.service
autofs.service
mdmonitor.service
multipathd.service
bluetooth.service
netfs.service
portreserve.service
saslauthd.service"

# snapshot systemd service

echo "take service snapshot"
/bin/systemctl snapshot default-srv-state

for s in $SERVICES_SYSD; do
    echo "service $s"
	systemctl is-enabled $s --quiet
	if [[ $? -eq $SUCCESS ]]; then
       		systemctl stop $s
       		systemctl disable $s
	fi
	echo
done

[ ! -d /opt/sysscript ] && mkdir /opt/sysscript

chkconfig --list >/opt/sysscript/oldstate.$UNIXTIME

for s in $SERVICES_CHCK; do
     echo "service $s"
       	chkconfig $s off
       	service $s stop
	echo
done

fi

# =====================================================================
# Configure audit

# for RHEL 5.x/6.x

if [ "$VERSION" = "5" ] || [ "$VERSION" = "6" ] ; then

echo
echo "Configure audit"

cp -p /etc/audisp/plugins.d/syslog.conf /etc/audisp/plugins.d/syslog.conf.old$UNIXTIME

cat <<END >/etc/audisp/plugins.d/syslog.conf
active = yes
direction = out
path = builtin_syslog
type = builtin
args = LOG_INFO
format = string
END

if [ "X`diff /etc/audisp/plugins.d/syslog.conf /etc/audisp/plugins.d/syslog.conf.old$UNIXTIME`" = "X" ]; then
	rm -f /etc/audisp/plugins.d/syslog.conf.old$UNIXTIME
fi

cp -p /etc/audit/auditd.conf /etc/audit/auditd.conf.old$UNIXTIME

cat <<END >/etc/audit/auditd.conf
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL
freq = 20
num_logs = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 5
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
##tcp_listen_port =
tcp_listen_queue = 5
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
END

if [ "X`diff /etc/audit/auditd.conf /etc/audit/auditd.conf.old$UNIXTIME`" = "X" ]; then
	rm -f /etc/audit/auditd.conf.old$UNIXTIME
fi

fi

# for RHEL 7.4

if [ "$VERSION" = "74" ]; then

	# syslog plugin block

	cp -p /etc/audisp/plugins.d/syslog.conf /etc/audisp/plugins.d/syslog.conf.old$UNIXTIME
	cp -p /etc/audit/auditd.conf /etc/audit/auditd.conf.old$UNIXTIME

	au_file="/etc/audisp/plugins.d/syslog.conf"

	grep -q '^active[[:space:]]*=[[:space:]]*yes' $au_file
	if [[ $? -ne $SUCCESS ]]; then
		sed -i -e "s/active[[:space:]]*=[[:space:]]*[a-z]*/active = yes/" $au_file
	fi

	# audit config set settings

	au_cfile="/etc/audit/auditd.conf"

	grep -q 'freq = 20' $au_cfile
	if [[ $? -ne $SUCCESS ]]; then
		sed -i -e "s/freq[[:space:]]*=[[:space:]]*[0-9]*/freq = 20/" $au_cfile
	fi

	grep -q 'num_logs = 4' $au_cfile
	if [[ $? -ne $SUCCESS ]]; then
        sed -i -e "s/num_logs[[:space:]]*=[[:space:]]*[0-9]*/num_logs = 4/" $au_cfile
	fi

	grep -q 'max_log_file = 5' $au_cfile
	if [[ $? -ne $SUCCESS ]]; then
        sed -i -e "s/max_log_file[[:space:]]*=[[:space:]]*[0-9]*/max_log_file = 5/" $au_cfile
	fi
fi

# RHEL 5/6

if [ "$VERSION" = "5" ] || [ "$VERSION" = "6" ] ; then

cp -p /etc/audit/audit.rules /etc/audit/audit.rules.old$UNIXTIME

cat <<END >/etc/audit/audit.rules
-e 1
-f 2
-b 8192
-r 0

-D

-a exclude,always -F msgtype=CWD
-a always,exit -F euid=0 -F perm=wxa -k root_action
-a exit,always -F dir=/etc/ -F perm=wa
-a exit,always -F dir=/var/log/ -F perm=wa
END

if [ "X`diff /etc/audit/audit.rules /etc/audit/audit.rules.old$UNIXTIME`" = "X" ]; then
	rm -f /etc/audit/audit.rules.old$UNIXTIME
fi


service auditd restart

fi

# RHEL 7.4

if [ "$VERSION" = "74" ]; then

cp -p /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.old$UNIXTIME

aur_f="/etc/audit/rules.d/audit.rules"

grep -q "\-e[[:space:]]*[0-9]*" $aur_f
if [[ $? -ne $SUCCESS ]]; then
	sed  -i -e "/-f[[:space:]]*[0-9]*/a # enable auditd" $aur_f
	sed  -i -e "/# enable auditd/a -e 1" $aur_f
	sed  -i -e "/-e[[:space:]]*[0-9]*/{G;}" $aur_f
fi

grep -q "\-f[[:space:]]*2" $aur_f
if [[ $? -ne $SUCCESS ]]; then
	sed -i -e "s/-f[[:space:]]*[0-9]*/-f 2/" $aur_f
fi

grep -q "\-r[[:space:]]*[0-9]*" $aur_f
if [[ $? -ne $SUCCESS ]]; then
        sed  -i -e "/-e[[:space:]]*[0-9]*/a # limit rate" $aur_f
        sed  -i -e "/# limit rate/a -r 0" $aur_f
        sed  -i -e "/-e[[:space:]]*[0-9]*/{G;}" $aur_f
fi


grep -q "\-a exclude,always -F msgtype=CWD" $aur_f
if [[ $? -ne $SUCCESS ]]; then
	sed  -i -e "/-r[[:space:]]*[0-9]*/a # rule line" $aur_f
	sed  -i "/# rule line/ a -a exclude,always -F msgtype=CWD \\
-a always,exit -F euid=0 -F perm=wxa -k root_action \\
-a exit,always -F dir=/etc/ -F perm=wa \\
-a exit,always -F dir=/var/log/ -F perm=wa" $aur_f

fi

/sbin/service auditd restart

fi

# =====================================================================
# Configure system log

echo
echo "Configure syslog"

cp -p /etc/services /etc/services.old$UNIXTIME

if [ "$VERSION" = "5" ]; then
	ed /etc/services <<END
/^syslog		514/d
i
#syslog		514/udp
syslog		529/udp
.
w
q
END

	ed /etc/services <<END
/^irc-serv	529\\/udp/d
i
#irc-serv	529/udp                 # IRC-SERV
.
w
q
END
	SYSLOG="syslog"
	SLPORT=""

elif [ "$VERSION" = "6" ]; then
	ed /etc/services <<END
/^syslog          514/d
i
#syslog          514/udp
syslog          529/udp
.
w
q
END

	ed /etc/services <<END
/^irc-serv        529\\/udp/d
i
#irc-serv        529/udp                 # IRC-SERV
.
w
q
END
	SYSLOG="rsyslog"
	SLPORT=":529"

fi


if [ "$VERSION" = "74" ]; then

echo
echo "Configure syslog port"

cp -p /etc/services /etc/services.old$UNIXTIME

fl_service="/etc/services"

grep -q "syslog[[:space:]]*514/udp" $fl_service
	if [[ $? -eq $SUCCESS ]]; then
		sed -i -e "s/syslog[[:space:]]*[0-9]*\/udp/syslog\t\t529\/udp/" $fl_service
	fi

grep -q "^irc-serv[[:space:]]*529\/udp" $fl_service
	if [[ $? -eq $SUCCESS ]]; then
		sed -i -e "s/irc-serv[[:space:]]*[0-9]*\/udp/#irc-serv\t529\/udp/" $fl_service
	fi

fi

if [ "X`diff /etc/services /etc/services.old$UNIXTIME`" = "X" ]; then
	rm -f /etc/services.old$UNIXTIME
fi

# for RHEL 5.x/6.x

if [ "$VERSION" = "5" ] || [ "$VERSION" = "6" ] ; then

cp -p /etc/$SYSLOG.conf /etc/$SYSLOG.conf.old$UNIXTIME

if [ "X`grep /var/log/audit_sys.log /etc/$SYSLOG.conf`" = "X" ]; then
	echo 'user.*		/var/log/audit_sys.log' >>/etc/$SYSLOG.conf
fi
if [ "X`grep 10.128.31.19 /etc/$SYSLOG.conf`" = "X" ]; then
	echo "*.debug		@10.128.31.19$SLPORT" >>/etc/$SYSLOG.conf
fi
if [ "X`grep user.none /etc/$SYSLOG.conf`" = "X" ]; then
	ed /etc/$SYSLOG.conf <<END
/var\\/log\\/messages/d
i
#*.info;mail.none;authpriv.none;cron.none			/var/log/messages
*.info;mail.none;authpriv.none;cron.none;user.none		/var/log/messages
.
w
q
END
fi

if [ "X`diff /etc/$SYSLOG.conf /etc/$SYSLOG.conf.old$UNIXTIME`" = "X" ]; then
	rm -f /etc/$SYSLOG.conf.old$UNIXTIME
fi

service $SYSLOG restart

fi

# for RHEL 7.4

if [ "$VERSION" = "74" ]; then

	cp -p /etc/rsyslog.conf /etc/rsyslog.conf.old$UNIXTIME

	rslog_c="/etc/rsyslog.conf"
	lg_host="/etc/rsyslog.d/loghost.conf"

	grep -q "*.info;mail.none;authpriv.none;cron.none;user.none" $rslog_c
	if [[ $? -ne $SUCCESS ]]; then
		sed -i -e "s/*.info;mail.none;authpriv.none;cron.none/*.info;mail.none;authpriv.none;cron.none;user.none/" $rslog_c
	fi

	grep -q "user.*[[:space:]]*/var/log/audit_sys.log" $rslog_c
	if [[ $? -ne $SUCCESS ]]; then
		echo "Add user logs"
		sed  -i -e "/local7.*/a # User logs" $rslog_c
		sed  -i -e "/# User logs/a user.*\t\t\t\t\t\t\t/var/log/audit_sys.log" $rslog_c
		sed  -i -e "/local7.*/{G;}" $rslog_c
	fi

	grep -q "#*.* @@remote-host:[0-9]*" $rslog_c
	if [[ $? -eq $SUCCESS ]]; then
		echo "Set LogHost"
		if [ ! -f $lg_host ]; then
			echo "*.* @10.128.31.19" > $lg_host
		else
			echo "LogHost already set on $lg_host file"
		fi
	fi

	/bin/systemctl restart rsyslog.service

fi

# =====================================================================
# Configure CRON

echo
echo "Configure CRON"

[ -f /var/spool/cron/root ] && cp -p /var/spool/cron/root /var/spool/cron/root.old$UNIXTIME

[ -f /var/spool/cron/root.old$UNIXTIME ] && cat /var/spool/cron/root.old$UNIXTIME | grep -v chkpassscript/chkpass >/var/spool/cron/root

echo >>/var/spool/cron/root
echo '0 4 * * 1 /opt/chkpassscript/chkpass_rhel.sh >/dev/null 2>&1' >>/var/spool/cron/root

service crond restart



# =====================================================================
# Configure mail

if [ "$VERSION" = "5" ] || [ "$VERSION" = "6" ] ; then

echo
echo "Configure mail system"

if [ "X`grep $rel_host /etc/hosts`" = "X" ]; then
		echo "$rel_ip	$rel_host" >>/etc/hosts
fi

if [ "X`grep -w $dom_fqdn /etc/hosts`" = "X" ]; then
		echo "$dom_ip	$dom_fqdn" >>/etc/hosts
fi

if [ "$VERSION" = "5" ]; then
	cp -p /etc/mail/sendmail.cf /etc/mail/sendmail.cf.old$UNIXTIME
	cat /etc/mail/sendmail.cf.old$UNIXTIME | sed 's/^DS.*/DS srv-mail-01/' >/etc/mail/sendmail.cf
	if [ "X`diff /etc/mail/sendmail.cf /etc/mail/sendmail.cf.old$UNIXTIME`" = "X" ]; then
		rm -f /etc/mail/sendmail.cf.old$UNIXTIME
	fi
	service sendmail restart
elif [ "$VERSION" = "6" ]; then
	if [ "X`grep '^relayhost' /etc/postfix/main.cf`" = "X" ]; then
		cp -p /etc/postfix/main.cf /etc/postfix/main.cf.old$UNIXTIME
		cat /etc/postfix/main.cf.old$UNIXTIME | grep -v '^relayhost' >/etc/postfix/main.cf
		ed /etc/postfix/main.cf <<END
/^#relayhost =/i
relayhost = $rel_host
.
w
q
END
		if [ "X`diff /etc/postfix/main.cf /etc/postfix/main.cf.old$UNIXTIME`" = "X" ]; then
			rm -f /etc/postfix/main.cf.old$UNIXTIME
		fi
		service postfix restart
	fi
fi

echo
echo "DONE."

fi

if [ "$VERSION" = "74" ]; then

	echo
	echo "Configure mail system"

	cp -p /etc/hosts /etc/hosts.old$UNIXTIME
	cp -p /etc/postfix/main.cf /etc/postfix/main.cf.old$UNIXTIME

	if [ "X`grep $rel_host /etc/hosts`" = "X" ]; then
		echo "$rel_ip	$rel_host" >>/etc/hosts
	fi

	if [ "X`grep -w $dom_fqdn /etc/hosts`" = "X" ]; then
		echo "$dom_ip	$dom_fqdn" >>/etc/hosts
	fi

	postfix_cfile="/etc/postfix/main.cf"

	grep -q "#relayhost[[:space:]]=[[:space:]]\[an.ip.add.ress\]" $postfix_cfile
	if [[ $? -eq $SUCCESS ]]; then
		sed -i -e "s/#relayhost[[:space:]]=[[:space:]]\[an.ip.add.ress\]/relayhost = "$rel_host"/" $postfix_cfile
	fi

	grep -xPq "^relayhost[[:space:]]=[[:space:]]$rel_host" $postfix_cfile
	if [[ $? -ne $SUCCESS ]]; then
		qr=`cat $postfix_cfile | grep ^relayhost`
		if [[ "$qr" = "relayhost = $rel_host" ]];then
			echo
		else
			sed -i -e "s/$qr/relayhost = "$rel_host"/" $postfix_cfile
		fi
	fi

	echo
	echo "DONE."

fi
