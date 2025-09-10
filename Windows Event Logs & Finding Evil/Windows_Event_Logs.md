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
- Retrieving events from the System log - `Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`
- Retrieving events from Microsoft-Windows-WinRM/Operational (use `-Oldest` to retrieve the oldest events) - `Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize`
- ``
