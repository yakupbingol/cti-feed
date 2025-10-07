# **CENTRAL THREAT INTELLIGENCE / EXTERNAL DYNAMIC LISTS**

This list contains malicious IP addresses. IP addresses are collected from various proprietary sources and updated daily.

## **Usage:**

### ONLY FORTIGATE
Usage : Security Fabric --> External connectors --> Create New --> Threat Feeds --> IP Address --> URI of external resource: **https://raw.githubusercontent.com/securewanltd/cti-feed/black-list.txt**

### ONLY PALO ALTO
Usage : Objects --> External Dynamic Lists --> Add --> Type: IP List --> Source: **https://raw.githubusercontent.com/securewanltd/cti-feed/black-list.txt**

### OTHER FIREWALL
Usage : Firewall --> Source Adress List : **https://raw.githubusercontent.com/securewanltd/threat-feed/black-list.txt**
