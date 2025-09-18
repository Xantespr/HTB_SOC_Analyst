## Event Tracing for Windows (ETW)
- event tracing sessions - `logman.exe query -ets`
- more data about provider subscribed to the session - `logman.exe query "EventLog-System" -ets`
- list of all available providers - `logman.exe query providers`
- filter providers - `logman.exe query providers | findstr "Winlogon"`
- functions and keywords of specific provider - `logman.exe query providers Microsoft-Windows-Winlogon`
### GUI
- Performance Monitor -> Data collector Sets -> Event Trace Sessions

## Analyzing Windows Event Logs En Masse
### Get-WinEvent
- identify the available logs - `Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize`
- get log providers - `Get-WinEvent -ListProvider * | Format-Table -AutoSize`
##

- Retrieving events from the System log - `Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`
- Retrieving events from Microsoft-Windows-WinRM/Operational (use `-Oldest` to retrieve the oldest events) - `Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`
- Retrieving events from .evtx Files - `Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`
##

- Filtering events with FilterHashtable - `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`
- Filtering but from exported file - `Get-WinEvent -FilterHashtable @{Path='C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`
- get event logs based on a date range (stard date is inclusive, and end exclusive, range in example 5/28/23 - 6/2/2023):
```
$startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
$endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

- Filtering events with FilterHashtable & XML (checking event ID 3 searching for given IP):
```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} |
`ForEach-Object {
$xml = [xml]$_.ToXml()
$eventData = $xml.Event.EventData.Data
New-Object PSObject -Property @{
    SourceIP = $eventData | Where-Object {$_.Name -eq "SourceIp"} | Select-Object -ExpandProperty '#text'
    DestinationIP = $eventData | Where-Object {$_.Name -eq "DestinationIp"} | Select-Object -ExpandProperty '#text'
    ProcessGuid = $eventData | Where-Object {$_.Name -eq "ProcessGuid"} | Select-Object -ExpandProperty '#text'
    ProcessId = $eventData | Where-Object {$_.Name -eq "ProcessId"} | Select-Object -ExpandProperty '#text'
}
}  | Where-Object {$_.DestinationIP -eq "52.113.194.132"}
```
##

- Filtering events with FilterXPath (identify installation of any Sysinternals tool) - ```Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[EventData[Data[@Name='Image']='C:\Windows\System32\reg.exe']] and *[EventData[Data[@Name='CommandLine']='`"C:\Windows\system32\reg.exe`" ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f']]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize```
- Filtering events with FilterXPath (any network connections to a particular suspicious IP address (52.113.194.132)) - `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='52.113.194.132']]"`
##

- Filtering events based on property values (select all properties of the objects passed to it) - `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1 | Select-Object -Property *`
- retrieves Process Create events from the Microsoft-Windows-Sysmon/Operational log, checks the parent command line of each event for the string -enc, and then displays all properties of any matching events as a list. - `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | Format-List`

## Detecting DLL Hijacking
1. download sysmon config: https://github.com/SwiftOnSecurity/sysmon-config
2. change "ImageLoad onmatch"  from "include" to "exclude"
3. load new config "sysmon.exe -c sysmonconfig-export.xml"
4. now logs will be collected, look for Event ID 7 and unsigned images loaded

## Detecting Unmanaged PowerShell/C-Sharp Injection
1. In Event Viewer look for "clr.dll" and "clrjit.dll" in processes that typically don’t require them. Event ID 7
2. If you want to look for parent, consider checking Event ID 8 = CreateRemoteThread, using TargetProcess id the same as the one you found in first step.

## Detecting Credential Dumping
1. Sysmon event ID 10 - look for source and target user being different in one event, or random file from random folder attempting to access LSASS `TargetImage: C:\Windows\system32\lsass.exe`

## strange parent-child relationship
1. Look for EVENT ID 1: Process creation
