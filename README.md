# WMI_Forensics
This repository contains scripts used to find evidence in WMI repositories, specifically OBJECTS.DATA files located at:

- C:\WINDOWS\system32\wbem\Repository\OBJECTS.DATA
- C:\WINDOWS\system32\wbem\Repository\FS\OBJECTS.DATA

## CCM_RUA_Finder.py
CCM_RUA_finder.py extracts SCCM software metering RecentlyUsedApplication logs from OBJECTS.DATA files.

### Usage
```CCM_RUA_Finder.py -i path\to\OBJECTS.DATA -o path\to\output.xls```

The output file will be TSV formatted. Excel will automatically parse TSV files with .xls extensions.

# Contact
David Pany - Mandiant (FireEye) - 2016

Twitter: @DavidPany

Please send  comments, bug reports, and questions to @DavidPany or push changes directly to GitHub
