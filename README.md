# 🛡️ Cloud SIEM Threat Hunting and Detection (Wazuh & AWS)

## **Executive Summary**
Designed and implemented a cloud-native Security Operations Center (SOC) hub using **Wazuh (SIEM/XDR)** on **AWS** to support real-world security operations. I architected a multi-node environment to monitor a **Windows Server 2022** endpoint, focusing on proactive **threat hunting**, **compliance engineering**, and **automated incident response**. This project demonstrates the full detection lifecycle: from identifying a vulnerability baseline of 26% to engineering custom rules that detect and remediate adversary behavior in real-time.

---

## **🏗️ Infrastructure & Security Architecture**
The architecture adheres to the **Principle of Least Privilege**, featuring a hardened manager node and encrypted telemetry tunnels.

![Architecture Diagram](diagram-image.jpg)

* **SIEM Manager**: Amazon Linux 2023 EC2 (AWS Cloud).
* **Monitored Endpoint**: Windows Server 2022 DataCenter (AWS Cloud).
* **Networking**: AWS Security Groups configured to permit only encrypted agent traffic (Port 1514/1515) and secure HTTPS management (Port 443).
* **Telemetry**: Real-time event streaming via AES-encrypted tunnels with automated reconnection logic.

---

## **🔍 SOC Use Cases & "Money Shot" Results**

### **1. Compliance Hardening (CIS Benchmark)**
**Objective:** Audit a production server against industry-standard benchmarks and remediate misconfigurations.
* **The Baseline**: An automated audit against the **CIS Microsoft Windows Server 2022 Benchmark** revealed an initial compliance score of **26%** with **263 critical failures**.
* **The Action**: Analyzed failure **ID 27003** (Minimum password length). I executed a system-wide policy hardening via PowerShell to enforce a 14-character minimum requirement.
* **The Result**: Successfully triggered a real-time **"Passed" event**, validating the effectiveness of the control and improving the overall security posture.

> ![Initial CIS Baseline](Screenshot%202025-12-26%20154111.png)
> *Initial Audit: Identifying 263 failed security checks.*

---

### **2. Threat Hunting & MITRE ATT&CK® Mapping**
**Objective:** Map endpoint telemetry to adversary tactics to provide actionable incident visibility.
* **Behavioral Detection**: Leveraged the Wazuh analysis engine to map events to **MITRE ATT&CK** tactics, identifying **Defense Evasion (T1562.001)** and **Privilege Escalation (T1484)**.
* **Integrity Auditing**: Established **File Integrity Monitoring (FIM)** for sensitive directories (`C:\WazuhDemo`), capturing over **300 unique alerts** with detailed audit trails (User ID, Process, Timestamp).

> ![MITRE ATT&CK Dashboard](Screenshot%202025-12-26%20152941.jpg)
> *SOC Workflow: Correlating endpoint telemetry with adversary techniques.*

---

### **3. Automated Malware Triage & Active Response**
**Objective:** Automate the containment of known threats using global threat intelligence.
* **API Integration**: Engineered a secure integration between the Wazuh manager and the **VirusTotal API** for automated file reputation analysis.
* **Simulation**: Created an **EICAR test file** on the endpoint. The SIEM instantly matched the file hash, queried VirusTotal, and generated a high-severity alert.
* **Incident Containment**: Configured **Active Response** to trigger the `remove-threat.exe` command upon detection of VirusTotal-flagged threats, effectively automating the containment phase.

> ![VirusTotal Alert](Screenshot%202025-12-26%20021624.png)
> *Detection Engineering: Automated high-severity alert for malicious hash detection.*

---

## **🛠️ Detection Engineering: Custom FIM Rules**
I engineered custom XML rules on the Wazuh Manager to flag suspicious tool transfers in sensitive directories, mapping them to **MITRE T1105 (Ingress Tool Transfer)**.

### **Implementation (`local_rules.xml`)**
```xml
<group name="syscheck,custom_fim,">
  <rule id="100001" level="7">
    <if_sid>554</if_sid>
    <field name="file">C:\\WazuhDemo</field>
    <description>Security Alert: New file detected in sensitive directory (C:\WazuhDemo).</description>
    <mitre><id>T1105</id></mitre>
  </rule>
</group>

````
### 🎯 SOC Analyst Core Competencies
* **Log Correlation**: Expert at analyzing journald, syslog, and Windows event channels to identify anomalous patterns.

* **Vulnerability Management**: Managing vulnerability-detection feeds with automated 60-minute update intervals.

* **Endpoint Management**: Proficient in managing ossec.conf for optimized Syscollector and FIM performance.


