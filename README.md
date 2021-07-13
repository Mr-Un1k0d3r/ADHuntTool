# ADHuntTool
official report for the AdHuntTool. C# Script used for Red Team. It can be used by Cobalt Strike execute-assembly or as standalone executable.

# How to use it

```
Usage: ADHuntTool.exe options domain [arguments]

ADHuntTool.exe Set
ADHuntTool.exe DumpLocalAdmin RingZer0 *optional*computername
ADHuntTool.exe DumpLocalGroup RingZer0 *optional*computername
ADHuntTool.exe DumpRemoteSession RingZer0 *optional*computername
ADHuntTool.exe DumpWkstaSession RingZer0 *optional*computername
ADHuntTool.exe CheckAdmin RingZer0 *optional*computername
ADHuntTool.exe DumpTrust RingZer0
ADHuntTool.exe DumpAllUsers RingZer0
ADHuntTool.exe DumpUser RingZer0 mr.un1k0d3r
ADHuntTool.exe DumpUsersEmail RingZer0
ADHuntTool.exe DumpAllComputers RingZer0 
ADHuntTool.exe DumpComputer RingZer0 DC01
ADHuntTool.exe DumpAllGroups RingZer0
ADHuntTool.exe DumpGroup RingZer0 "Domain Admins"
ADHuntTool.exe DumpPasswordPolicy RingZer0
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

# Credit 

Mr.Un1k0d3r RingZer0 Team

Tazz0 RingZer0 Team
