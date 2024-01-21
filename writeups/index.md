[Home](/) |

# Writeups

## [Vulnlab: Lock](../vulnlab/machines/lock/)

**22\. January 2024**

[Lock](../vulnlab/machines/lock/) is an easy machine starting with `Gitea` access tokens and some CI/CD exploitation for getting a foothold onto the box. For user we will have to decrypt `mRemoteNG` RDP configuration file to get a user's password and RDP into the machine. For root we will exploit a vulnerability in PDF24 that will allow us SYSTEM level access after setting opportunistic lock on a file the PDF24 repair process tries to write to.

<br>

## [Vulnlab: Forgotten](../vulnlab/machines/forgotten/)

**18\. December 2023**

[Forgotten](../vulnlab/machines/forgotten/) is a easy (junior) level machine on [Vulnlab](https://www.vulnlab.com/) involving exploitation of a forgotten web installer of `LimeSurvey` survey application. After successful installation, the `LimeSurvey` allowed us to upload a malicious PHP plugin and we were able to get Remote Code Execution landing in docker instance. The box ends with a very nice way of leveraging root access to a docker instance and shared folder with the host for privilege escalation.

<br>

## [HTB: Gofer (Part 1)](../htb/machines/Gofer/)

[Gofer](../htb/machines/Gofer/) is a hard difficulty Linux machine on [Hack The Box](https://.hackthebox.com) involving the exploitation of HTTP verb tampering and chaining SSRF with Gopher protocol to send a phishing e-mail and compromise the user with malicious LibreOffice document. This writeup is divided into 2 parts. First part contains the web exploitation part of the machine and phishing to get the user and the second part will contain binary exploitation for privilege escalation.

<br>

## [Vulnlab: Retro](../vulnlab/machines/Retro/)

[Retro](../vulnlab/machines/Retro/) is a easy machine on [Vulnlab](https://www.vulnlab.com/). It involves some password guessing, provides a interesting insight into pre-created domain computer accounts and how to abuse them and ends with a ESC1 Active Directory Certificate Services abuse.

<br>

## [HTB: Escape](../htb/machines/Escape/)

[Escape](../htb/machines/Escape/) is a medium difficulty machine which involved stealing of NTLM hashes and abusing AD CS certificate templates.
