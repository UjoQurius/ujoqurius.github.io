# Vulnlab: Forgotten

Forgotten is a easy (junior) level machine on [Vulnlab](https://www.vulnlab.com/) involving exploitation of a forgotten web installer of `LimeSurvey` survey application. The installation allowed to supply a remote MySQL server instance and we could configure the web application to use our server as it's database. After successful installation, the `LimeSurvey` allowed us to upload a malicious PHP plugin and we were able to get Remote Code Execution landing in docker instance. This may seem like a bit far fetched scenario, however, as the machine's creator ([xct](https://twitter.com/xct_de)) pointed out, this is something that he encountered on a real life pentest. The box ends with a very nice way of leveraging root access to a docker instance and shared folder with the host.

I hope you enjoy this write up, let's get into it!

![](https://1897091482-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FI3I73FFqB6GvT8N5Mt1N%2Fuploads%2F3MjKIWEyfP0Bo5Q8XLHH%2Fforgotten_slide.png?alt=media&token=1d62bc50-3cee-4744-b22f-8a07e23d1445)

## Nmap

As with every machine, let's start with an Nmap scan. I use my own Rust wrapper which you can find [here](https://github.com/qur1us/rustmap). Let's look at the results.

```
# Nmap 7.94SVN scan initiated Thu Dec 14 18:05:10 2023 as: nmap -sC -sV -oA nmap/forgotten -p 22,80 -Pn 10.10.97.103
Nmap scan report for 10.10.97.103
Host is up (0.027s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0:cb:84:9b:d1:a5:0e:5a:b8:81:38:3b:e7:6c:35:f2 (ECDSA)
|_  256 32:4d:ea:89:3a:5f:1c:4f:3a:25:36:54:8d:c9:73:68 (ED25519)
80/tcp open  http    Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: 403 Forbidden
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 14 18:05:18 2023 -- 1 IP address (1 host up) scanned in 7.57 seconds
```

