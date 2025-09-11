## Search Processing Language (SPL)
- search in main index -  `index="main" "*UNKNOWN*"`
- excluded field "User" - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User`
- results in a tabular format - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image`
- rename a field in the search results - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rename Image as Process`
- removes duplicate events - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | dedup Image`
- sort desc - the most recent events are shown first - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time`
- The stats command performs statistical operations - This query will return a table where each row represents a unique combination of a timestamp (_time) and a process (Image) - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image`
- This query will return a table where each row represents a unique timestamp (_time) and each column represents a unique process (Image) - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | chart count by _time, Image`
- creates a new field Process_Path which contains the lowercase version of the Image field - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_Path=lower(Image)`
- The rex command extracts new fields from existing ones using regular expressions - `index="main" EventCode=4662 | rex max_match=0 "[^%](?<guid>{.*})" | table guid`
- earliest and latest commands limit searches to specific time periods- `index="main" earliest=-7d EventCode!=1`
- Subsearches - `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image ] | table _time, Image, CommandLine, User, ComputerName`
##

- list of all data sources - `| metadata type=sources index=* | table source`
- all fields - `sourcetype="WinEventLog:Security" | table *`
- only names of fields - `sourcetype="WinEventLog:Security" | fieldsummary`

##
- events distribted over time - `index=* sourcetype=* | bucket _time span=1d | stats count by _time, index, sourcetype | sort - _time`
- 10 rarest combinations of indexes and sourcetypes - `index=* sourcetype=* | rare limit=10 index, sourcetype`
- unique - `| stats dc(user) as unique_users`
