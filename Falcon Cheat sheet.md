
```
CHEAT SHEET

  

*** epoch to human readable ***

  

| convert ctime(ProcessStartTime_decimal)

  

*** combine Context and Target timestamps **

  

| eval endpointTime=mvappend(ProcessStartTime_decimal, ContextTimeStamp_decimal)

  

*** UTC Localization ***

  

| eval myUTCoffset=-4

| eval myLocalTime=ProcessStartTime_decimal+(60*60*myUTCoffset)

  

*** combine Falcon Process UUIDs ***

  

| eval falconPID=mvappend(TargetProcessId_decimal, ContextProcessId_decimal)

  

*** string swaps ***

  

| eval systemType=case(ProductType_decimal=1, "Workstation", ProductType_decimal=2, "Domain Controller", ProductType_decimal=3, "Server")

  

*** shorten string ***

  

| eval shortCmd=substr(CommandLine,1,250)

  

*** regex field ***

  

rex field=DomainName "[@\.](?<tlDomain>\w+\.\w+)$"

```