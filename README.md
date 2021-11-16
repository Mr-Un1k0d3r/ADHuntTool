# ADHuntTool
official report for the AdHuntTool. C# Script used for Red Team. It can be used by Cobalt Strike execute-assembly or as standalone executable.

# How to use it

Note that `DumpCertificateTemplates` and `DumpPasswordPolicy` need the full base 

Ex: domain name is `ringzer0.local` you need to specify the domain as `ringzer0,DC=local`

This will generate the following query under the hood

```
beacon> execute-assembly C:\users\dev\Desktop\ADHuntTool.exe dumpcertificatetemplates ringzer0,DC=local -verbose
CA Name is:
Connecting to: LDAP://CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=ringzer0,DC=local
Querying:      (&(!name=AIA))
name                    : RINGZER0-RZDC-CA

Connecting to: LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=ringzer0,DC=local
Querying:      (&(name=*))
name                    : User
displayName             : User
distinguishedName       : CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=RINGZER0,DC=local
msPKI-Cert-Template-OID : 1.3.6.1.4.1.311.21.8.7352012.6162934.10046593.3535065.1065136.82.1.1
msPKI-Enrollment-Flag   : 41
```

List of supported features

You can specify the `-acl` switch to dump access control for each item

```
ADHuntTool.exe DumpCertificateTemplates RINGZER0,DC=CA -acl

CA Name is:
Connecting to: LDAP://CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=RINGZER0,DC=CA
Querying:      (&(!name=AIA))
ntSecurityDescriptor    : Group: RINGZER0\Enterprise Admins
DACL
------------
Type: Access Allowed
Permissions: Create All Child Objects|Delete All Child Objects|List Contents|All Validated Writes|Read All Properties|Write All Properties|Delete Subtree|List Object|All Extended Rights|Delete|Read Permissions|Modify Permissions|Modify Owner
Trustee: Domain Administrators
------------
Type: Access Allowed
Permissions: Create All Child Objects|Delete All Child Objects|List Contents|All Validated Writes|Read All Properties|Write All Properties|Delete Subtree|List Object|All Extended Rights|Delete|Read Permissions|Modify Permissions|Modify Owner
Trustee: RINGZER0\Enterprise Admins
------------
...


```

The command output can be redirected to a file using the `-tofile`. Filename is the unixtimestamp

Standard commands

```
Usage: ADHuntTool.exe options domain [arguments]

ADHuntTool.exe Set
ADHuntTool.exe DumpLocalAdmin RingZer0 *optional*computername
ADHuntTool.exe DumpLocalGroup RingZer0 *optional*computername
ADHuntTool.exe DumpRemoteSession RingZer0 *optional*computername
ADHuntTool.exe DumpWkstaSession RingZer0 *optional*computername
ADHuntTool.exe CheckAdmin RingZer0 *optional*computername
ADHuntTool.exe DumpTrust RingZer0
ADHuntTool.exe DumpSamAccount RingZer0
ADHuntTool.exe DumpAllUsers RingZer0
ADHuntTool.exe DumpUser RingZer0 mr.un1k0d3r
ADHuntTool.exe DumpUsersEmail RingZer0
ADHuntTool.exe DumpAllComputers RingZer0 
ADHuntTool.exe DumpComputer RingZer0 DC01
ADHuntTool.exe DumpAllGroups RingZer0
ADHuntTool.exe DumpGroup RingZer0 "Domain Admins"
ADHuntTool.exe DumpPasswordPolicy Ringzer0,DC=local
ADHuntTool.exe DumpCertificateTemplates Ringzer0,DC=local
ADHuntTool.exe DumpPwdLastSet RingZer0
ADHuntTool.exe DumpLastLogon RingZer0
ADHuntTool.exe CheckManaged RingZer0
ADHuntTool.exe DumpLapsPassword RingZer0 *optional*computername  
ADHuntTool.exe DumpUserPassword RingZer0   
ADHuntTool.exe DumpRemoteSession RingZer0  *optional*computername  
ADHuntTool.exe PasswordBruteForce RingZer0 *optional*username (samaccountname) 
ADHuntTool.exe GetShare target *optional*Domain\Username Password
ADHuntTool.exe GetService target *optional*Domain\Username Password
```

The `-verbose` switch can be added to get verbose output.

# ADHuntUser

Search through DC event log user using domain name, username or ip.

```
ADHuntUser.exe username mrun1k0d3r
ADHuntUser.exe domain RINGZER0
ADHuntUser.exe ip 192.168.1.10
```

# Credit 

Mr.Un1k0d3r RingZer0 Team

Tazz0 RingZer0 Team
