# **CENTRAL THREAT INTELLIGENCE / EXTERNAL DYNAMIC LISTS**

This list contains malicious IP addresses. IP addresses are collected from various proprietary sources and updated daily. We offer you several lists. Here's a description of each.

* **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list.txt** = It is a general Black List.
* **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list-level1.txt** = This is the list we've compiled, stripped of duplicate IP addresses. This is where the general list comes from.
* **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list-level2.txt** = Contains IP addresses that are repeated twice in all collected lists.
* **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list-level3.txt** = Contains IP addresses that occur 3 times in all collected lists.
* **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list-level4.txt** = Contains IP addresses that occur 4 times in all collected lists.
* **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list-level5.txt** = It includes IP addresses that occur five or more times in all compiled lists. This list is the most stable. It contains the most common IP addresses that appear five or more times in our list.
* **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/malware-sha256.txt** = Contains Malware IoC (SHA256) information.

## **Usage:**

### ONLY FORTIGATE
Usage : Security Fabric --> External connectors --> Create New --> Threat Feeds --> IP Address --> URI of external resource: **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list.txt**

### ONLY PALO ALTO
Usage : Objects --> External Dynamic Lists --> Add --> Type: IP List --> Source: **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list.txt**

### OTHER FIREWALL
Usage : Firewall --> Source Adress List : **https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list.txt**


Note: If you have too many problems using "black-list.txt", we recommend you to use "black-list-level5.txt" list.
