import paramiko
import requests
import json

# ==========================
# CONFIG
# ==========================

WAZUH_SERVER = "192.168.56.10"
USERNAME = "bharath"
PASSWORD = "3600"

OLLAMA_MODEL = "llama3.2:3b"

# ==========================
# GET ALERTS FROM WAZUH
# ==========================

try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(
        hostname=WAZUH_SERVER,
        username=USERNAME,
        password=PASSWORD
    )

    stdin, stdout, stderr = ssh.exec_command(
        "tail -10 /var/ossec/logs/alerts/alerts.json"
    )

    raw_alerts = stdout.read().decode()
    errors = stderr.read().decode()

    ssh.close()

except Exception as e:
    print(f"\n[!] SSH Connection Failed: {e}")
    exit()

if errors:
    print(errors)
    exit()

# ==========================
# PARSE ALERTS
# ==========================

parsed_alerts = []

for line in raw_alerts.strip().split("\n"):
    try:
        alert = json.loads(line)

        parsed_alerts.append({
            "timestamp": alert.get("timestamp"),
            "level": alert.get("rule", {}).get("level"),
            "rule_id": alert.get("rule", {}).get("id"),
            "description": alert.get("rule", {}).get("description"),
            "agent": alert.get("agent", {}).get("name"),
            "source_ip": alert.get("data", {}).get("srcip", "N/A"),
            "user": alert.get("data", {}).get("dstuser", "N/A")
        })

    except:
        pass

print("\n========== WAZUH ALERTS ==========\n")

for item in parsed_alerts:
    print(json.dumps(item, indent=2))
    print()

# ==========================
# BUILD AI PROMPT
# ==========================
prompt = f"""
You are a Senior SOC Analyst with Blue Team experience.

Your job is to analyze Wazuh alerts accurately.

CRITICAL RULES:

1. NEVER invent MITRE ATT&CK techniques.
2. ONLY use MITRE techniques explicitly present in the Wazuh alert data.
3. If no MITRE ATT&CK information exists in the alert:
   MITRE: None

4. NEVER classify normal administrator activity as malicious.

Examples of potentially legitimate activity:
- SSH authentication success
- PAM login opened
- PAM login closed
- Successful sudo execution
- Service startup changes
- Software protection service events
- Administrator logins

5. Only classify activity as Suspicious or Malicious if evidence exists such as:
- Multiple failed logins
- Brute force attempts
- Malware detections
- IOC matches
- Privilege abuse
- Persistence mechanisms
- Suspicious external IPs
- Known attack signatures

6. Choose ONLY ONE severity:
Low
Medium
High
Critical

7. Keep the response concise.
8. Maximum response length: 15 lines.
9. SOC style output only.
10. No explanations outside the required format.

Return EXACTLY:

ALERT:
<one line summary>

SEVERITY:
<Low|Medium|High|Critical>

MITRE:
<Technique IDs or None>

IOC:
- User: <value>
- Source IP: <value>
- Host: <value>

INVESTIGATION:
- <command>
- <command>
- <command>

VERDICT:
<Benign|Suspicious|Malicious>

REMEDIATION:
- <action>
- <action>

WAZUH ALERTS:

{json.dumps(parsed_alerts, indent=2)}
"""

# ==========================
# SEND TO OLLAMA
# ==========================

print("\n========== SENDING TO OLLAMA ==========\n")

try:
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama3.2:3b",
            "prompt": prompt,
            "stream": False,
            "temperature": 0.1
        },
        timeout=300
    )

    response.raise_for_status()

    result = response.json()["response"]

    print("\n========== AI ANALYSIS ==========\n")
    print(result)

except Exception as e:
    print(f"\n[!] Ollama Error: {e}")