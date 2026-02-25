# Rearc Cyber Quest - Threat Detection Engineering Assessment
**Solved By:** Dhwanit Samir Pandya


## Overview

This assessment analyzes 28,017 Sysmon events forwarded via Cribl to detect 
macro-based phishing activity. The core hypothesis is that Microsoft Office 
applications making unprompted DNS queries is a strong indicator of a malicious macro beaconing to a Command and Control server.

---

## Process

### Part 1 - Data Loading and Parsing
Loaded raw Sysmon events into a Bronze layer and parsed them into a structured Silver layer. I used `get_json_object()` instead of `from_json()` to handle mixed event types cleanly, the dataset contains EventCodes 1, 3, 10, 22, and 23, each with different fields in the nested `_raw` JSON.

### Part 2 - Detection Engineering
Built a detection query targeting EventCode 22 (DNS Query) events where the initiating process was a Microsoft Office application. The query returned 8 results : 7 legitimate Microsoft telemetry domains and 1 suspicious domain (www.mediafire.com).

### Part 3 - Normalization, Alerting and Enrichment
Normalized detection results to OSSEM standard field names, which is purpose built for Windows Sysmon data. Packaged the suspicious finding into a high-fidelity alert with MITRE ATT&CK mappings (T1566.001 and T1071.004) and a deterministic SHA256 alert ID to prevent duplicates across repeated detection runs.

Enriched the alert using 3 threat intelligence sources:
- **WHOIS** - domain registration context
- **URLhaus** - confirmed 678 malicious URLs on mediafire.com since 2019
- **VirusTotal** - domain reputation and vendor verdicts

### Extra Part - Incident Investigation
Went beyond the detection to investigate the full attack chain using EventCode 3 (Network Connection), EventCode 11 (File Create), and EventCode 23 (File Delete) logs:
- Confirmed winword.exe made 3 outbound connections to mediafire.com (104.16.54.48)
- Discovered the malicious document was named `asyncrat.doc` - associated with the AsyncRAT Remote Access Trojan
- Found 113 file deletions consistent with cleanup behavior seen in malware families.

**Final verdict: High Confidence Potential Compromise**

---

## Key Design Decisions

- **get_json_object over from_json** - handles mixed event types without requiring a fixed schema across all event codes
- **OSSEM over ECS** - the data is Windows Sysmon logs, OSSEM maps security events to MITRE ATT&CK techniques, focusing heavily on Windows processes, network connections, and registry modifications
- **SHA256 alert IDs** - deterministic hashing ensures idempotency across repeated detection runs, prevents duplicate alerts
- **Three enrichment sources** - chosen to cover domain registration, malware hosting history, and vendor reputation without overwhelming the analyst
- **API keys in .env** - excluded from version control via .gitignore for security
- **High-fidelity alerting** - filtered known Microsoft telemetry domains to reduce false positives and alert fatigue

---

## Tech Stack

- Python 3.14.2
- Apache Spark / PySpark 3.5.8
- Java 17 LTS
- Jupyter Notebook
- URLhaus API (abuse.ch)
- VirusTotal API
- python-whois

---

## References

- **Sysmon EventCode 22 (DNS Query)** : https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90022
- **PySpark SQL Documentation** : https://spark.apache.org/docs/latest/sql-getting-started.html#running-sql-queries-programmatically
- **PySpark SHA2 Function** : https://dlcdn.apache.org/spark/docs/3.4.3/api/python/reference/pyspark.sql/api/pyspark.sql.functions.sha2.html
- **OSSEM EventCode 22 Data Dictionary** : https://github.com/OTRF/OSSEM-DD/blob/afd9b27897346dfa3b3f43d2d403c3f5c5f86214/windows/sysmon/events/event-22.yml
- **MITRE ATT&CK T1566.001**: https://attack.mitre.org/techniques/T1566/001/
- **MITRE ATT&CK T1071.004**: https://attack.mitre.org/techniques/T1071/004/
- **OSSEM CDM DNS Entity** : https://ossemproject.com/cdm/entities/dns.html
- **Elastic ECS DNS Schema** : https://www.elastic.co/docs/reference/ecs/ecs-dns
- **python-whois Library** : https://pypi.org/project/python-whois/
- **URLhaus API Documentation** : https://urlhaus-api.abuse.ch/
- **VirusTotal Domain Info API** : https://docs.virustotal.com/reference/domain-info
- **AsyncRAT Malware Explained** : https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/asyncrat-malware-explained/

---

## Personal Note

This was one of the more engaging technical assessments I have worked through.The dataset felt real, the hypothesis made sense, and I found myself going deeper than the requirements just out of curiosity.Ending up with a potential AsyncRAT compromise from what started as a single suspicious DNS query was a great feeling. That progression is exactly the kind of work I want to be doing, and this assessment gave me a genuine taste of it.