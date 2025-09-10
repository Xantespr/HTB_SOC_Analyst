## Event Tracing for Windows (ETW)
- event tracing sessions - `logman.exe query -ets`
- more data about provider subscribed to the session - `logman.exe query "EventLog-System" -ets`
- list of all available providers - `logman.exe query providers`
- filter providers - `logman.exe query providers | findstr "Winlogon"`
- functions and keywords of specific provider - `logman.exe query providers Microsoft-Windows-Winlogon`
