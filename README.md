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
env                    \\\\ Environment variables
cat .bashrc
crunch 6 6 -t Lab%%% > wordlist \\\\ Creating a wordlist for bruteforce
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
