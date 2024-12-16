
Process Injection query ([T1055](https://attack.mitre.org/techniques/T1055))
Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005))Process Injection ([T1055](https://attack.mitre.org/techniques/T1055))Dynamic-link Library Injection ([T1055.001](https://attack.mitre.org/techniques/T1055/001/))
```
#event_simpleName=ProcessInjection 

| ("Reflective*" "*alicious*")

| table([@timestamp, Tactic, DetectName, @id, #event_simpleName, CommandLine, ReflectiveDllName], limit=20000)
```

Persistence through registry
```
#event_simpleName=AsepValueUpdate event_platform=*

| table([@timestamp, ComputerName, RegObjectName, RegOperationType, RegStringValue, RegType, RegValueName, TargetFileName], limit=20000)
```

Modify Registry [T1112] https://attack.mitre.org/techniques/T1112
```

#event_simpleName=RegistryOperationDetectInfo event_platform=*

Tactic = "*Persistence*"

| table([@timestamp, Tactic, Technique, @id, Patterid_decimal, TemplateInstanceid_decimal, FileName, RegOpTypeStr, RegObjName, RegStringValue, Source, FileName], limit=20000)

```

Phishing
Example Gunter clicks link in email from noreply@sktlocal.it and downloads NTFVersion.exe
```

#event_simpleName=* event_platform=*

Techniques = "*Phishing"
Techniques = "Drive-by Compromise"
Techniques = "User Execution"

##example
| ParentBaseFileName = msedge.exe


| table([@timestamp, @id, Patterid_decimal, ComputerName, ParentBaseFileName, HostUrl, FilePath, FileName], limit=20000)

```

User Execution ([T1204](https://attack.mitre.org/techniques/T1204))
```
#event_simpleName=* event_platform=*

Tactic = "*Initial Access"

| table([@timestamp, DetectName, event_simpleName, Commandline, file, HostUrl], limit=20000)
```

Boot or Logon Autostart execution
```
#event_simpleName=* event_platform=*
Technique = Boot or Logon Autostart Execution
| table([@timestamp, ComputerName, event_simpleName, RegObjectName, RegStringValue, RegValueName], limit=20000)
```

Process Injection ([T1055](https://attack.mitre.org/techniques/T1055)) *meh*
```
#event_simpleName=* event_platform=*
Technique = Process Injection
| table([@timestamp, ComputerName, event_simpleName, InjectorImageFileName, InjecteeImageFileName, ExecutableBytes], limit=20000)
```

Process Discovery ([T1057](https://attack.mitre.org/techniques/T1057))
For example explorer.exe enumerates process list via CreateToolhelp32Snapshot
```
#event_simpleName=* event_platform=*
Technique = Process Injection
| table([@timestamp,  #event_simpleName, ComputerName, @id, cdata], limit=20000)
```

Account Discovery ([T1087](https://attack.mitre.org/techniques/T1087))
For example msedge.exe enumerates all users on the local machine via NetUserEnum
*meh*
```
#event_simpleName=* 
Technique = Account Discovery
| table([@timestamp,  #event_simpleName, ComputerName, @id, CommandLine, FileName, ModuleExportName], limit=20000)
```

File and Directory Discovery ([T1083](https://attack.mitre.org/techniques/T1083))
For example msedge.exe enumerates Gunter's files via FindFirstFile & FindNextFile​
```
#event_simpleName=* 
Technique = File and Directory Discovery, Native API
```

Archive Collected Data ([T1560](https://attack.mitre.org/techniques/T1560))
For example msedge.exe bzip2 compresses discovery output in memory 
*kiv*
```
#event_simpleName= ProcessInjection, HttRequestDetect
Technique = *

| table([@timestamp,  #event_simpleName, ComputerName, @id, SourceFalconPid, DestFalconPid, RefLoadInfo, ProcInjectionInfo, HttpReqInfo], limit=20000)
```

Data Encoding ([T1132](https://attack.mitre.org/techniques/T1132))
For example msedge.exe base64 encodes discovery output in memory
```
#event_simpleName= ProcessInjection, HttRequestDetect
Technique = Data Encoding or Standard Encoding

| table([@timestamp, FileName, @id, AmsMatchMemoryContents])
```

Proxy ([T1090](https://attack.mitre.org/techniques/T1090))
For Example msedge.exe connects to adversary's compromised proxy - shoppingbeach[.]org
```
#event_simpleName= *
| table([@timestamp,  #event_simpleName, ComputerName, @id, SourceFalconPid, DestFalconPid, RefLoadInfo, ProcInjectionInfo, HttpReqInfo], limit=20000)
```

Application Layer Protocol ([T1071](https://attack.mitre.org/techniques/T1071))
For example msedge.exe connects to shoppingbeach[.]org over HTTP protocol
```
#event_simpleName= *
| table([@timestamp,  #event_simpleName, ComputerName, @id, Commandline, HttpMethodStr, HttpReqHeader], limit=20000)
```

Permission Groups Discovery ([T1069](https://attack.mitre.org/techniques/T1069))
For example cmd.exe executes various net group commands
Discovery ([TA0007](https://attack.mitre.org/tactics/TA0007))Permission Groups Discovery ([T1069](https://attack.mitre.org/techniques/T1069))Domain Groups ([T1069.002](https://attack.mitre.org/techniques/T1069/002/))
```
#event_simpleName= *
| Commandline = net group*
| table([@timestamp,  #event_simpleName, ComputerName, @id, Commandline, FileName], limit=20000)
```