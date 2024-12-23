
External Domain Owner Lookup
```
#event_simpleName=NetworkConnectIP4 | RemoteAddressIP4=*
      | !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/16", "192.168.0.0/16", "192.254.0.0/16"])
      | table([NetworkConnectIP4, RemotePort], limit = 1000)
      | groupBy([NetworkConnectIP4, RemotePort], limit = 10, function=count())
      | sort(_count, order=desc)
```

check client the amount of DNS requests sent to domain and it's subdomains.
```
#event_simpleName=DnsRequest | DomainName=?mydomain
      | table([DomainName], limit = 1000)
      | groupBy([DomainName], limit = 1000, function=count())
      | sort(_count, order=desc)
```

Information machine/system/host

```
#event_simpleName=* event_platform=Win

| readFile(aid_master_main.csv)

| ComputerName = "(insert_name)"

| readFile(aid_master_details.csv)
```

Lookup file in Crowdstrike
```
#event_simpleName=ProcessRollup2 event_platform="Win"

| match(file="sha1-ioc-malware.csv", field="SHA1HashData", column=sha1, include=[FileName, SHA1HashData], strict=true, ignoreCase=true)
```

Hunting system binary masquerading w/o lookup file

```
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win ImageFileName=/\\Windows\\(System32|SysWOW64)\\/

| ImageFileName=/(\\Device\\HarddiskVolume\d+)?(?<FilePath>\\.+\\)(?<FileName>.+$)/

| lower(field=FileName, as=FileName)

| FilePath != "*CrowdStrike*"

| groupBy([FileName, FilePath], function=([count(aid, distinct=true, as=uniqueEndpoints), count(aid, as=executionCount)]))

| uniqueEndpoints:=format("%,.0f",field="uniqueEndpoints")

| executionCount:=format("%,.0f",field="executionCount")

| expectedFileName:=rename(field="FileName")

| expectedFilePath:=rename(field="FilePath")

| details:=format(format="The file %s has been executed %s time on %s unique endpoints in the past 30 days.\nThe expected file path for this binary is: %s.", field=[expectedFileName, executionCount, uniqueEndpoints, expectedFilePath])

| select([expectedFileName, expectedFilePath, uniqueEndpoints, executionCount, details])
```

**Finding lolbin**

```
// Get all process executions for Windows systems

#event_simpleName=ProcessRollup2 event_platform="Win"

// Check to make sure FileName is on our LOLBINS list located in lookup file

| match(file="win_lolbins.csv", field="FileName", column=FileName, include=[FileName, Description, Paths, URL], strict=true)

// Massage ImageFileName so a true key pair value can be created that combines file path and file name

| regex("(\\\\Device\\\\HarddiskVolume\\d+)?(?<ShortFN>.+)", field=ImageFileName, strict=false)

| ShortFN:=lower("ShortFN")

| FileNameLower:=lower("FileName")

| RunningKey:=format(format="%s_%s", field=[FileNameLower, ShortFN])

// Check to see where the executing file's key doesn't match an expected key value for an LOLBIN

| !match(file="win_lolbins.csv", field="RunningKey", column=key, strict=true)

// Output results to table

| table([@timestamp, aid, ComputerName, UserName, ParentProcessId, ParentBaseFileName, FileName, ShortFN, Paths, CommandLine, Description, Paths, URL])

// Clean up "Paths" to make it easier to read

| Paths =~replace("\, ", with="\n")

// Rename two fields so they are more explicit

| rename([[ShortFN, ExecutingFilePath], [Paths, ExpectFilePath]])

// Add Link for Process Explorer

| rootURL := "https://falcon.crowdstrike.com/" /* US-1 */

//| rootURL  := "https://falcon.us-2.crowdstrike.com/" /* US-2 */

//| rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" /* Gov */

//| rootURL  := "https://falcon.eu-1.crowdstrike.com/"  /* EU */

| format("[PrEx](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "ParentProcessId"], as="ProcessExplorer")

// Add link back to LOLBAS Project

| format("[LOLBAS](%s)", field=[URL], as="Link")

// Remove unneeded fields

| drop([rootURL, ParentProcessId, URL])
```

Watching the watchers

```
// Get successful Falcon console logins

EventType=Event_ExternalApiEvent OperationName=userAuthenticate Success=true


// Get ASN Details for OriginSourceIpAddress

| asn(OriginSourceIpAddress, as=asn)
  
// Omit ZScaler infra

| asn.org!=/ZSCALER/

//Get IP Location for OriginSourceIpAddress

| ipLocation(OriginSourceIpAddress)


// Get geohash with precision of 2; precision can be adjusted as desired

| geohash(lat=OriginSourceIpAddress.lat, lon=OriginSourceIpAddress.lon, precision=2, as=geohash)


// Get RDNS value, if available, for OriginSourceIpAddress

| rdns(OriginSourceIpAddress, as=rdns)


//Set default values for blank fields

| default(value="Unknown Country", field=[OriginSourceIpAddress.country])

| default(value="Unknown City", field=[OriginSourceIpAddress.city])

| default(value="Unknown ASN", field=[asn.org])

| default(value="Unknown RDNS", field=[rdns])


// Create unified IP details field for easier viewing

| format(format="%s (%s, %s) [%s] - %s", field=[OriginSourceIpAddress, OriginSourceIpAddress.country, OriginSourceIpAddress.city, asn.org, rdns], as=ipDetails)

  

// Aggregate details by UserId and geoHash

| groupBy([UserId, geoHash], function=([count(as=logonCount), min(@timestamp, as=firstLogon), max(@timestamp, as=lastLogon), collect(ipDetails)]))

// Look for geohashes with fewer than 5 logins; logonCount can be adjusted as desired

| test(logonCount<200)


// Calculate time delta and determine span between first and last login

| timeDelta := lastLogon-firstLogon

| formatDuration(timeDelta, from=ms, precision=4, as=timeDelta)

  

// Format timestamps

| formatTime(format="%Y-%m-%dT%H:%M:%S", field=firstLogon, as="firstLogon")

| formatTime(format="%Y-%m-%dT%H:%M:%S", field=lastLogon, as="lastLogon")

  

// Create link to geohash map for easy cartography

| format("[Map](https://geohash.softeng.co/%s)", field=geoHash, as=Map)

  

// Order fields as desired

| select([UserId, firstLogon, lastLogon, timeDelta, logonCount, Map, ipDetails])
```

Lookup file with rmm_list.csv

```

// Get all Windows process execution events

| #event_simpleName=ProcessRollup2 event_platform=Win 

// Check to see if FileName value matches the value or a known RMM tools as specified by our lookup file

| match(file="rmm_list.csv", field=[FileName], column=rmm_binary, ignoreCase=true)

  

// Do some light formatting

| regex("(?<short_binary_name>\w+)\.exe", field=FileName)

| short_binary_name:=lower("short_binary_name")

| rmm_binary:=lower(rmm_binary)

  
// Aggregate by RMM program name

| groupBy([rmm_program], function=([

    collect([rmm_binary]), 

    collect([short_binary_name], separator="|"),  

    count(FileName, distinct=true, as=FileCount), 

    count(aid, distinct=true, as=EndpointCount),

    max(ContextTimeStamp, as=LastSeen),

    count(aid, as=ExecutionCount)

]))


| LastSeen:=formatTime(format="%F %T %Z", field="LastSeen")

  

// Create case statement to display what Custom IOA regex will look like

| case{

    FileCount>1 | ImageFileName_Regex:=format(format=".*\\\\(%s)\\.exe", field=[short_binary_name]);

    FileCount=1 | ImageFileName_Regex:=format(format=".*\\\\%s\\.exe", field=[short_binary_name]);

}


// More formatting

| description:=format(format="Unexpected use of %s observed. Please investigate.", field=[rmm_program])

| rename([[rmm_program,RuleName],[rmm_binary,BinaryCoverage]])

| table([RuleName, EndpointCount, ExecutionCount, description, ImageFileName_Regex, BinaryCoverage, LastSeen], sortby=ExecutionCount, order=desc)
```

Falcon query rmm tool with lookup file rmm_executables_list.csv

```
/ Get all Windows Process Executions

#event_simpleName=ProcessRollup2 event_platform=Win

  

// Create exclusions for approved filenames

| !in(field="FileName", values=[mstsc.exe], ignoreCase=true)

  

// Check to see if FileName matches our list of RMM tools

| match(file="rmm_executables_list.csv", field=[FileName], column=rmm, ignoreCase=true)

  

// Create pretty ExecutionChain field

| ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId])

  

// Perform aggregation

| groupBy([@timestamp, aid, ComputerName, UserName, ExecutionChain, CommandLine, TargetProcessId, SHA256HashData], function=[], limit=max)

  

// Create link to VirusTotal to search SHA256

| format("[Virus Total](https://www.virustotal.com/gui/file/%s)", field=[SHA256HashData], as="VT")

  

// SET FLACON CLOUD; ADJUST COMMENTS TO YOUR CLOUD

| rootURL := "https://falcon.crowdstrike.com/" /* US-1*/

//rootURL  := "https://falcon.eu-1.crowdstrike.com/" ; /*EU-1 */

//rootURL  := "https://falcon.us-2.crowdstrike.com/" ; /*US-2 */

//rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" ; /*GOV-1 */

  

// Create link to Indicator Graph for easier scoping by SHA256

| format("[Indicator Graph](%sintelligence/graph?indicators=hash:'%s')", field=["rootURL", "SHA256HashData"], as="Indicator Graph")

  

// Create link to Graph Explorer for process specific investigation

| format("[Graph Explorer](%sgraphs/process-explorer/graph?id=pid:%s:%s)", field=["rootURL", "aid", "TargetProcessId"], as="Graph Explorer")

  

// Drop unneeded fields

| drop([SHA256HashData, TargetProcessId, rootURL])
```

Newly seen DNS query

```
// Get DnsRequest events tied to PowerShell

#event_simpleName=DnsRequest event_platform=Win ContextBaseFileName=powershell.exe


// Use case() to create buckets; "Current" will be within last one day and "Historical" will be anything before the past 1d as defined by the time-picker

| case {

    test(@timestamp < (now() - duration(1d))) | HistoricalState:="1";

    test(@timestamp > (now() - duration(1d))) | CurrentState:="1";

}

// Set default values for HistoricalState and CurrentState

| default(value="0", field=[HistoricalState, CurrentState])


// Check to make sure that the DomainName field as NOT been seen in the Historical dataset and HAS been seen in the current dataset

| HistoricalState=0 AND CurrentState=1

  

// Aggregate by Historical or Current status and DomainName; gather helpful metrics

| groupBy([DomainName], function=[max("HistoricalState",as=HistoricalState), max(CurrentState, as=CurrentState), max(ContextTimeStamp, as=LastSeen), count(aid, as=ResolutionCount), count(aid, distinct=true, as=EndpointCount), collect([FirstIP4Record])])

// Convert LastSeen to Human Readable

| LastSeen:=formatTime(format="%F %T %Z", field="LastSeen")

// Get GeoIP data for first IPv4 record of domain name

| ipLocation(FirstIP4Record)


// SET FLACON CLOUD; ADJUST COMMENTS TO YOUR CLOUD

| rootURL := "https://falcon.crowdstrike.com/" /* US-1*/

//rootURL  := "https://falcon.eu-1.crowdstrike.com/" ; /*EU-1 */

//rootURL  := "https://falcon.us-2.crowdstrike.com/" ; /*US-2 */

//rootURL  := "https://falcon.laggar.gcw.crowdstrike.com/" ; /*GOV-1 */


// Create link to Indicator Graph for easier scoping

| format("[Indicator Graph](%sintelligence/graph?indicators=domain:'%s')", field=["rootURL", "DomainName"], as="Indicator Graph")


// Create link to Domain Search for easier scoping

| format("[Domain Search](%sinvestigate/dashboards/domain-search?domain=%s&isLive=false&sharedTime=true&start=7d)", field=["rootURL", "DomainName"], as="Search Domain")

// Drop HistoricalState, CurrentState, Latitude, Longitude, and rootURL (optional)

| drop([HistoricalState, CurrentState, FirstIP4Record.lat, FirstIP4Record.lon, rootURL])

  

// Set default values for GeoIP fields to make output look prettier (optional)



| default(value="-", field=[FirstIP4Record.country, FirstIP4Record.city, FirstIP4Record.state])
```

Failed multiple logins followed by success

```
// Filter on authentication events
#event_simpleName=/^(UserLogon|UserLogonFailed2)$/

// Add wildcard filters to reduce the scope if needed. 
| wildcard(field=aip, pattern=?AgentIP, ignoreCase=true)
| wildcard(field=aid, pattern=?aid, ignoreCase=true)
| wildcard(field=UserName, pattern=?UserName, ignoreCase=true)

// Add in Computer Name to results. This is not needed in FLTR or FSR.
//| $crowdstrike/fltr-core:zComputerName()

// Add another wildcard filters to reduce the scope if needed.
| wildcard(field=ComputerName, pattern=?ComputerName, ignoreCase=true)

// Filter out usernames that we don't want to alert on.
| UserName!=/(\$$|^DWM-|LOCAL\sSERVICE|^UMFD-|^$|-|SYSTEM)/

// Make UserNames all lowercase.
| lower(UserName, as=UserName)

// Make working with events easier and setting auth status
| case { 
    #event_simpleName=UserLogonFailed2 
      | authStatus:="F" ; 
    #event_simpleName=UserLogon 
      | authStatus:="S" ;
  }

// Run a series that makes sure everything is in order and starts with a failure and ends with a success within timeframe. 
// Change your timeframes here within maxpause and maxduration. 
| groupBy([UserName, aip], function=series(authStatus, separator="", endmatch={authStatus=S}, maxpause=15min, maxduration=15min, memlimit=1024), limit=max)
| authStatus=/F*S/i
| failedLoginCount:=length("authStatus")-1

// Set your failed login count threshold here. 
| failedLoginCount>=5

// Set the min and max duration for equal or less than above. 
// Modify min duration to use the test function similar to max duration if you wish to set anything via human readable vs millisecond format.
| _duration>0
| test(_duration<duration(15min))

// Format time duration to make readable. 
| firstAuthSuccess:=@timestamp+_duration
| formatTime(format="%c", as=firstAuthFailure)
| formatTime(field=firstAuthSuccess, format="%c", as=firstAuthSuccess)
| formatDuration(_duration)
| table([UserName, aip, _duration, firstAuthFailure, firstAuthSuccess, failedLoginCount], limit=1000, sortby=failedLoginCount)

```
