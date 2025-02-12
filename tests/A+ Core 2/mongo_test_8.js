{
  "category": "aplus2",
  "testId": 8,
  "testName": "Practice Test #8 (Very Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A user reports intermittent network connectivity issues on a Windows workstation. They can sometimes access websites, but the connection frequently drops. Pings to the default gateway are consistently successful. Pings to external websites are intermittent, and `nslookup` sometimes resolves domain names correctly but often returns a 'Request timed out' or 'Server failed' error. You've already tried `ipconfig /flushdns` and `ipconfig /release` & `/renew`. What is the MOST likely cause, and how would you proceed with *further* diagnosis?",
      "options": [
        "A faulty network cable; replace the cable.",
        "An intermittent hardware problem with the network adapter; replace the adapter.",
        "An intermittent issue with the user's configured DNS servers, or network congestion/packet loss between the user's computer and the DNS servers. Use `nslookup` to test *different* DNS servers (e.g., Google Public DNS - 8.8.8.8, Cloudflare - 1.1.1.1) and use `ping` and `tracert` to test connectivity *to the DNS servers themselves*.",
        "The user's web browser is corrupted; reinstall it."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Intermittent DNS resolution failures, while local connectivity is stable, strongly point to a problem with the *DNS servers themselves* or the network path *to* those servers. The key is to *isolate* the issue. Testing with *different* DNS servers (like Google's 8.8.8.8) helps determine if the problem is with the user's *primary* DNS server. Using `ping` and `tracert` *to the DNS server IPs* helps diagnose connectivity issues *to the DNS servers*. A cable or adapter problem would likely cause more consistent issues. A browser problem is unlikely to cause DNS resolution failures at the system level.",
      "examTip": "When troubleshooting intermittent DNS resolution problems, systematically test with *different* DNS servers and use `ping`/`tracert` to check connectivity *to those DNS servers* to isolate the issue."
    },
    {
      "id": 2,
      "question": "You are investigating a suspected malware infection on a Linux server. You need to examine the system's process list for any unusual or suspicious processes. Which command provides the MOST comprehensive and detailed view of running processes, including their parent-child relationships (process tree), user context, and command-line arguments?",
      "options": [
        "top",
        "ps aux",
        "pstree -p",
        "htop"
      ],
      "correctAnswerIndex": 2, // 1 is also correct
      "explanation": "`pstree -p` displays a visual tree of running processes, showing the parent-child relationships. The `-p` option includes the process IDs (PIDs). This hierarchical view can be very helpful in identifying suspicious processes that might have been launched by other malicious processes. `ps aux` provides a comprehensive list, but not in a tree format. `top` and `htop` are dynamic process monitors, good for real-time monitoring, but `pstree` is better for visualizing the process hierarchy.",
      "examTip": "Use `pstree -p` on Linux to visualize the process tree and identify parent-child relationships, which can be crucial for understanding how processes were launched and for detecting suspicious activity."
    },
    {
      "id": 3,
       "question": "A user reports slow performance on their Windows workstation. Task Manager shows high CPU utilization, but no single process appears to be consuming all the CPU resources. Resource Monitor also shows high CPU usage, but the culprit isn't immediately obvious. You've already ruled out malware. What is the NEXT BEST tool to use for a more in-depth analysis of CPU usage, potentially identifying a driver or system component causing the problem?",
      "options":[
        "System Configuration (msconfig.exe)",
        "Disk Cleanup",
       "Windows Performance Recorder (WPR) and Windows Performance Analyzer (WPA), part of the Windows Assessment and Deployment Kit (ADK).",
        "Event Viewer"
      ],
      "correctAnswerIndex": 2,
      "explanation": "WPR/WPA provides *extremely* detailed performance tracing and analysis capabilities. It can capture a trace of system activity (including CPU usage, disk I/O, memory usage, etc.) and then allows you to analyze that trace in detail, breaking down CPU usage by process, thread, module (driver), and even individual function calls. This level of detail is often necessary to pinpoint the cause of subtle performance problems. msconfig is for startup, Disk Cleanup is for disk space, and Event Viewer is for logs (which *might* contain clues, but WPR/WPA is the *direct* performance analysis tool).",
      "examTip": "Learn to use Windows Performance Recorder (WPR) and Windows Performance Analyzer (WPA) for in-depth performance analysis in Windows; they are powerful tools for diagnosing complex performance issues."
    },
    {
        "id": 4,
        "question":"A user is unable to access a specific internal web server. They can access other internal resources and the internet. You can ping the web server's IP address from the user's computer, and `nslookup` resolves the server's hostname correctly. Other users *can* access the web server. What is the MOST likely cause on the *user's* computer?",
        "options":[
            "The web server is down.",
           "A local firewall rule on the user's computer is blocking access to the web server's IP address or port (80/443), a proxy server is misconfigured, or there's an incorrect entry in the 'hosts' file.",
            "The user's network adapter driver is corrupted.",
            "The user's DNS server settings are incorrect."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If *other* users can access the server, and the affected user can ping the server's IP *and* DNS resolves correctly, the problem is almost certainly local to the *user's computer*. A local firewall rule (blocking the specific IP or port), a misconfigured proxy server, or an incorrect entry in the 'hosts' file (overriding DNS) are the most likely culprits. The server being down is ruled out by other users' access. A driver problem would likely cause more general connectivity issues. DNS is already ruled out.",
        "examTip":"When troubleshooting website access problems where basic connectivity and DNS resolution are working, *and other users can access the site*, focus on local factors on the affected computer: firewall, proxy, 'hosts' file."
    },
    {
       "id": 5,
        "question": "You are configuring a secure wireless network using WPA2-Enterprise. What is the role of the RADIUS server in this setup?",
        "options":[
            "To provide encryption for the wireless traffic.",
           "To authenticate individual users against a central database (e.g., Active Directory) using 802.1X, providing user-level access control and accounting.",
            "To assign IP addresses to wireless clients.",
            "To manage the wireless network's SSID and channel settings."
        ],
        "correctAnswerIndex": 1,
        "explanation": "In WPA2-Enterprise, the RADIUS server handles *user authentication*. It verifies user credentials against a central database (like Active Directory) and grants or denies access based on those credentials. This provides much stronger security and better accountability than a shared password (PSK). Encryption is handled by WPA2 itself (using AES). IP addresses are assigned by a DHCP server. SSID and channel settings are managed on the access point/wireless controller.",
        "examTip": "WPA2-Enterprise uses 802.1X and a RADIUS server for *user authentication*, providing a more secure and manageable wireless environment than WPA2-Personal (which uses a shared password)."
    },
    {
        "id": 6,
        "question":"You are investigating a potential data breach on a Linux server. You need to examine the system logs to see who has logged in recently and what commands they have executed. Which log files would be MOST relevant to this investigation?",
        "options":[
            "`/var/log/messages`",
           "`/var/log/auth.log` (or `/var/log/secure` on some systems) for login/authentication events, and potentially `/var/log/audit/audit.log` (if auditd is configured) or user's `~/.bash_history` files (with caution) for command history.",
            "`/var/log/syslog`",
            "`/var/log/dmesg`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`/var/log/auth.log` (or `/var/log/secure` on some distributions like Red Hat/CentOS) records authentication-related events, including successful and failed login attempts, SSH logins, and sudo usage. This is crucial for tracking user access. `/var/log/audit/audit.log` (if the `auditd` service is configured) provides *very* detailed auditing, including command execution.  A user's `~/.bash_history` file stores their command history *within their bash shell*, but this is easily manipulated by the user and shouldn't be solely relied upon. `/var/log/messages` and `/var/log/syslog` are general system logs, and `dmesg` shows kernel messages; these *might* contain relevant information, but are less targeted than the authentication-specific logs.",
        "examTip": "On Linux systems, examine `/var/log/auth.log` (or `/var/log/secure`) for login/authentication events, and consider using the audit system (`auditd`) for more comprehensive auditing, including command execution."
    },
     {
        "id": 7,
        "question": "A user reports that their Windows computer is experiencing random Blue Screen of Death (BSOD) errors. You've checked for overheating, run Windows Memory Diagnostic (no errors), and used Driver Verifier (no immediate crashes). What is the NEXT BEST step to try to diagnose the cause of the BSODs?",
        "options":[
            "Reinstall the operating system.",
          "Analyze the memory dump files (minidumps or a full memory dump) created during the BSODs using a debugging tool like WinDbg.",
            "Run `chkdsk`.",
            "Run System Restore."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Memory dump files (created during BSODs) contain valuable information about the state of the system at the time of the crash, including the specific error code, the drivers loaded, and the memory contents. Analyzing these dumps with a debugging tool like WinDbg (part of the Windows SDK) can often pinpoint the cause of the BSOD (a faulty driver, hardware problem, etc.). Reinstalling the OS is a last resort. `chkdsk` checks for disk errors. System Restore might help, but analyzing the dumps provides more *specific* diagnostic information.",
        "examTip": "Learn to use WinDbg (or a similar debugging tool) to analyze Windows memory dump files; this is a crucial skill for troubleshooting BSODs and other system crashes."
    },
    {
        "id":8,
        "question": "You are troubleshooting a website that is loading slowly. Using the browser's developer tools (Network tab), you notice that a particular image file is taking a very long time to download. What is the MOST likely cause, *assuming the server itself is not overloaded*?",
        "options":[
           "The user's DNS server is slow.",
            "The image file is very large (high resolution, unoptimized), or there is network congestion or high latency between the user's computer and the web server.",
            "The user's computer has a virus.",
            "The user's web browser is outdated."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If a *specific* file (like an image) is slow to download, while *other* resources on the same site load normally, the problem is likely with the *file itself* (it's too large, unoptimized) or with network conditions *between* the user and the server (congestion, high latency). Slow DNS would affect the *initial* connection to the website, not the download of individual files *after* the connection is established. A virus or outdated browser are less likely to cause this *specific* symptom.",
        "examTip": "Use the browser's developer tools (Network tab) to analyze website loading performance and identify slow-loading resources; optimize images and other assets for faster delivery."
    },
     {
        "id": 9,
        "question":"You are configuring a new hard drive in a Windows computer. You want to use the GPT (GUID Partition Table) partitioning scheme. Which firmware interface is REQUIRED for booting from a GPT disk in most cases?",
        "options":[
           "BIOS",
            "UEFI (Unified Extensible Firmware Interface)",
            "CMOS",
            "POST"
        ],
        "correctAnswerIndex": 1,
        "explanation": "UEFI is generally required to boot from GPT disks. While some older BIOS systems *might* have limited GPT support, UEFI is the standard firmware interface for modern systems and provides full GPT support. BIOS is the older legacy firmware. CMOS is the memory that stores BIOS settings. POST is the power-on self-test.",
        "examTip": "UEFI is the modern firmware interface and is generally required for booting from GPT disks; BIOS is the legacy interface and has limitations with GPT."
    },
    {
        "id": 10,
        "question": "You are investigating a suspected malware infection on a Windows computer. You want to see which programs are configured to run automatically when Windows starts. You've already checked Task Manager's Startup tab and the `msconfig` Startup tab. Where else should you check for autostart locations, including *less common* ones that malware might use?",
        "options":[
          "The user's Documents folder.",
            "The Windows Registry (specifically, the Run, RunOnce, RunServices, and RunServicesOnce keys under HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER), Scheduled Tasks, and Windows Services.",
            "The Program Files folder.",
            "The Control Panel."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Malware often uses various registry keys and system features to ensure persistence.  The `Run`, `RunOnce`, `RunServices`, and `RunServicesOnce` keys in both `HKEY_LOCAL_MACHINE` (system-wide) and `HKEY_CURRENT_USER` (user-specific) are common autostart locations, but *less obvious* than the Startup folder. Scheduled Tasks and Services can *also* be used to launch programs automatically. The other options are less relevant for *automatic* startup (though malware *might* place files in those locations).",
        "examTip": "Thoroughly investigate *all* potential autostart locations in Windows (Task Manager, msconfig, Registry Run keys, Scheduled Tasks, Services) when hunting for malware or troubleshooting startup problems. Tools like Autoruns (from Sysinternals) can simplify this process."
    },
    {
        "id": 11,
        "question": "A user reports their computer is making a repetitive clicking noise, especially when accessing files.  The computer is also running slower than usual. What is the MOST likely cause?",
        "options":[
           "A failing cooling fan.",
            "A failing hard drive (if it's a traditional HDD).",
            "A failing power supply.",
            "A failing RAM module."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A repetitive clicking noise is a classic symptom of a failing *mechanical* hard drive (HDD). The clicking sound is often caused by the read/write head repeatedly trying to access data and failing. Failing fans usually make buzzing, whirring, or rattling noises. Power supply failures often manifest as shutdowns or restarts. RAM failures usually cause crashes or BSODs, not clicking sounds.",
        "examTip": "A repetitive clicking noise from a computer is a strong indicator of a failing hard drive (HDD); back up data immediately."
    },
     {
        "id": 12,
        "question":"What is 'DLL hijacking'?",
        "options":[
           "A type of social engineering attack.",
          "A type of attack where a malicious DLL (Dynamic Link Library) file is placed in a directory that is searched *before* the legitimate DLL, causing the operating system to load the malicious DLL instead of the intended one.",
            "A type of denial-of-service attack.",
            "A type of network sniffing attack."
        ],
        "correctAnswerIndex": 1,
        "explanation": "DLL hijacking exploits the way Windows searches for DLL files. If an attacker can place a malicious DLL with the *same name* as a legitimate DLL in a directory that's searched *earlier* in the search path, the operating system will load the malicious DLL, potentially giving the attacker control over the application or system. It's not social engineering, a DoS attack, or network sniffing *directly*.",
        "examTip": "DLL hijacking is a serious vulnerability; keep your software up-to-date and be cautious about running untrusted applications, especially with elevated privileges."
    },
     {
        "id": 13,
        "question": "You are analyzing network traffic with Wireshark. You want to filter the displayed packets to show only traffic destined for a specific port (e.g., port 443 for HTTPS). Which Wireshark display filter would you use?",
        "options":[
           "`ip.addr == 192.168.1.1`",
            "`tcp.port == 443` or `udp.port == 443` (depending on whether you're interested in TCP or UDP traffic)",
            "`http`",
            "`icmp`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`tcp.port == 443` filters for TCP traffic destined for port 443 (HTTPS).  `udp.port == 443` would filter for UDP traffic on port 443 (less common for HTTPS). `ip.addr` filters by IP address, `http` filters for HTTP traffic (usually port 80), and `icmp` filters for ICMP (ping) traffic.",
        "examTip": "Use `tcp.port` or `udp.port` in Wireshark display filters to isolate traffic based on the destination port number."
    },
    {
        "id": 14,
        "question": "You are troubleshooting a Windows computer that is experiencing intermittent network connectivity problems. You suspect a problem with the network adapter driver. You've already tried rolling back the driver and updating to the latest driver from the manufacturer's website, but the problem persists. What is the NEXT BEST step?",
        "options":[
          "Reinstall the operating system.",
            "Check the Windows Event Viewer (specifically the System log) for any error messages related to the network adapter or network connectivity. Also, consider testing the network adapter with a diagnostic utility provided by the adapter manufacturer.",
            "Run `chkdsk`.",
            "Replace the network cable."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If driver updates and rollbacks don't resolve the issue, checking the Windows Event Viewer (System log) for error messages related to the network adapter is a good next step. These logs might provide clues about the underlying cause.  Also, many network adapter manufacturers provide diagnostic utilities that can test the hardware for problems. Reinstalling the OS is too drastic. `chkdsk` checks for disk errors. Replacing the cable is a good idea, *but checking for error logs first is better*. ",
        "examTip": "Consult the Windows Event Viewer (System log) for error messages related to hardware or drivers when troubleshooting intermittent problems."
    },
    {
        "id": 15,
        "question":"You are configuring a web server to use HTTPS. You have obtained an SSL/TLS certificate. What is the role of the 'private key' associated with the certificate?",
        "options":[
          "To encrypt all data sent *from* the client *to* the server.",
            "The private key is kept secret on the server and is used to decrypt data encrypted by the client with the server's *public* key (which is part of the certificate).  It's also used to digitally sign data sent *from* the server, proving its authenticity.",
            "To encrypt all data sent *from* the server *to* the client.",
            "To store user passwords."
        ],
        "correctAnswerIndex": 1,
        "explanation": "In HTTPS (and SSL/TLS in general), there's a *key pair*: a public key and a private key. The *public key* is included in the certificate and is distributed to clients. The *private key* is kept *secret* on the server. The private key is used for two crucial functions: *decrypting* data that was encrypted by the client using the server's public key, and *digitally signing* data sent from the server, allowing clients to verify the server's identity. It's not used to *encrypt* all data sent *from* the server (the client uses the *public* key for that). It doesn't store passwords.",
        "examTip": "Protect the private key associated with your SSL/TLS certificate extremely carefully; if it's compromised, attackers can impersonate your server or decrypt sensitive data."
    },
    {
        "id":16,
        "question": "A user is unable to access a specific website. Other websites are working normally. You can ping the website's IP address successfully from the user's computer, and `nslookup` resolves the domain name correctly. What is the MOST likely cause on the *user's* computer?",
        "options":[
            "The website's server is down.",
           "A firewall rule on the user's computer is blocking access to the website's IP address or port, a proxy server is misconfigured, or there's an incorrect entry in the Windows 'hosts' file.",
            "The user's DNS server settings are incorrect.",
            "The user's network cable is faulty."
        ],
        "correctAnswerIndex": 1,
        "explanation":"If you can *ping the IP address* and `nslookup` works, DNS resolution and basic network connectivity are *not* the problem. The issue is likely local to the user's computer: a firewall rule blocking the specific website (IP or port), a misconfigured proxy server, or an entry in the 'hosts' file overriding DNS. If the *website's server* were down, the ping by IP would likely also fail. DNS is already ruled out. A cable issue would likely cause more general problems.",
        "examTip": "When troubleshooting website access problems where basic connectivity and DNS are working, focus on local factors: firewall, proxy, 'hosts' file."
    },
    {
        "id": 17,
        "question": "You are troubleshooting a Linux server and need to view the system's kernel ring buffer, which contains messages from the kernel (including boot messages and hardware-related information). Which command would you use?",
        "options":[
           "dmesg",
            "journalctl",
            "syslog",
            "messages"
        ],
        "correctAnswerIndex": 0,
        "explanation": "`dmesg` (display message) prints the kernel ring buffer, which contains messages from the kernel, including boot-time messages, hardware detection, and driver information. `journalctl` is the command to interact with systemd's journal (a more modern logging system). `syslog` and `messages` are related to system logging, but don't specifically show the kernel ring buffer.",
        "examTip": "Use `dmesg` on Linux to view kernel messages, which can be helpful for troubleshooting hardware problems or driver issues."
    },
    {
        "id": 18,
        "question": "What is 'salting' in the context of password hashing, and why is it important for security?",
        "options":[
           "Adding a random string to the password *before* hashing it, making it more difficult for attackers to use precomputed rainbow tables to crack passwords.",
            "Encrypting the password with a strong encryption algorithm.",
            "Storing the password in a plain text file.",
            "Using a short and simple password."
        ],
        "correctAnswerIndex": 0,
        "explanation": "Salting involves adding a random, unique string (the salt) to each password *before* it's hashed. This makes each password hash unique, even if two users choose the same password. Salting prevents attackers from using precomputed rainbow tables (which only work for *unsalted* hashes) to crack passwords efficiently. It's not encryption *itself*, storing passwords in plaintext, or using weak passwords.",
        "examTip": "Always use strong, unique salts when hashing passwords; this is a critical security measure to protect against rainbow table attacks."
    },
     {
        "id": 19,
        "question": "You are configuring a firewall and want to implement 'stateful inspection.' What is the KEY characteristic of a stateful firewall?",
        "options":[
           "It only examines individual packets in isolation, without considering the context of a connection.",
            "It tracks the state of network connections (e.g., TCP streams) and uses this information to make filtering decisions, allowing return traffic for established connections to pass through automatically.",
            "It only blocks traffic based on IP addresses and ports.",
            "It only allows traffic based on application-layer data."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Stateful inspection is a key feature of modern firewalls. It keeps track of *active connections* (e.g., TCP connections). When a connection is initiated from the internal network (allowed), the firewall remembers this and *automatically* allows the *return* traffic associated with that connection. This is much more secure and efficient than stateless firewalls, which examine each packet *independently*. Stateful firewalls *can* consider IP addresses and ports, *but* they go beyond that by tracking connection state.",
        "examTip": "Stateful firewalls are more secure and efficient than stateless firewalls because they track the state of network connections."
    },
    {
       "id": 20,
        "question": "A user reports that their computer is exhibiting slow performance. You open Task Manager and notice that the 'System' process is consuming a significant amount of CPU resources. What is the 'System' process in Windows, and what might cause it to use high CPU?",
        "options":[
            "The 'System' process is a web browser; high CPU usage is normal.",
           "The 'System' process (PID 4) is a core Windows process that hosts kernel-mode threads, including device drivers. High CPU usage by the 'System' process often indicates a driver problem, a hardware issue, or potentially system file corruption.",
            "The 'System' process is a third-party application; you should uninstall it.",
            "The 'System' process is a virus; you should immediately delete it."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The 'System' process (with Process ID 4) is a *critical* Windows component that hosts kernel-mode threads, including those for device drivers. High CPU usage by the 'System' process is *abnormal* and often points to a driver problem (a buggy or malfunctioning driver), a hardware issue (causing the driver to work harder), or potentially system file corruption. It's not a web browser, a third-party application (normally), or a virus *itself* (though malware *might* try to inject code into the System process).",
        "examTip": "High CPU usage by the 'System' process (PID 4) often indicates a driver problem, a hardware issue, or system file corruption; investigate thoroughly."
    },
    {
        "id": 21,
        "question": "You are configuring a Linux system and want to ensure that a particular script runs automatically every time the system boots. You've decided to use `systemd`, the system and service manager. Which of the following is the BEST way to achieve this?",
        "options":[
           "Add the script to the `/etc/rc.local` file.",
            "Create a systemd service unit file (e.g., `myscript.service`) in `/etc/systemd/system/`, define the service's behavior (when to start, dependencies, etc.), and then enable the service using `systemctl enable myscript.service`.",
            "Add the script to the user's `.bashrc` file.",
            "Use the `at` command."
        ],
        "correctAnswerIndex": 1,
        "explanation": "On systems using `systemd`, the *correct* way to manage services (including those that should start at boot) is to create a systemd service unit file. This file defines how the service should be started, stopped, and managed. `/etc/rc.local` is a legacy method that *might* still work on some systems, but it's not the recommended approach with `systemd`. `.bashrc` is for user-specific shell settings, not system-wide services. `at` is for scheduling one-time tasks.",
        "examTip": "Learn to create and manage systemd service unit files on Linux systems that use `systemd`; this is the standard way to manage services and daemons."
    },
    {
        "id": 22,
        "question": "A user reports that their computer is displaying a 'No Boot Device Found' error message. You've checked the BIOS settings, and the hard drive is detected. The boot order is also correct. What is a *less common*, but still possible, cause you should investigate?",
        "options":[
           "The monitor cable is faulty.",
            "Corruption of the boot sector or the BCD (Boot Configuration Data) store, *even if* the hard drive itself is functional.",
            "The keyboard is not working.",
            "The network cable is unplugged."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If the hard drive is detected and the boot order is correct, but the system still can't find a bootable operating system, the problem is likely with the *boot sector* or the *BCD store* on the hard drive. These contain critical information about how to load the operating system. Corruption in these areas can prevent booting, even if the rest of the hard drive is fine. The other options are unrelated to the boot process.",
        "examTip": "Use the Windows Recovery Environment (boot from installation media) and tools like `bootrec.exe` (and, in more complex situations, `bcdedit`) to repair boot sector or BCD problems."
    },
     {
        "id": 23,
        "question":"What is 'typosquatting' in the context of cybersecurity?",
        "options":[
           "A type of denial-of-service attack.",
            "Registering domain names that are similar to legitimate domain names (e.g., 'goggle.com' instead of 'google.com'), hoping users will mistype the address and be redirected to a malicious website.",
            "A type of malware that encrypts files.",
            "A type of social engineering attack."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Typosquatting exploits common typing errors. Attackers register domain names that are slight misspellings of popular websites, hoping users will accidentally visit their malicious site instead of the legitimate one. It's not a DoS attack, malware that encrypts, or social engineering *directly* (though it can be *used* as part of a phishing or malware distribution scheme).",
        "examTip": "Be careful when typing website addresses; typosquatting relies on user errors to redirect them to malicious sites."
    },
    {
        "id": 24,
        "question":"You are troubleshooting a network connectivity issue where a computer can access some websites but not others. You suspect a problem with MTU (Maximum Transmission Unit) settings. What is MTU, and how can an incorrect MTU setting cause connectivity problems?",
        "options":[
           "MTU is the maximum size of a packet (in bytes) that can be transmitted over a network. If the MTU is set *too high* for a particular network path, packets might be fragmented or dropped, leading to connectivity problems.",
            "MTU is the speed of the network connection.",
            "MTU is the type of encryption used on the network.",
            "MTU is the IP address of the default gateway."
        ],
        "correctAnswerIndex": 0,
        "explanation": "MTU defines the *largest* packet size that can be transmitted without fragmentation. If a device sends packets larger than the MTU supported by a router or other network device along the path, those packets will either be *fragmented* (broken into smaller pieces) or *dropped* (if fragmentation is not allowed). This can cause connectivity issues, especially for websites or applications that rely on larger packets. It's not the connection speed, encryption type, or gateway IP.",
        "examTip": "Incorrect MTU settings can cause intermittent network connectivity problems; use the `ping` command with the `-l` (Windows) or `-s` (Linux) option and the `-f` (Windows) or `Don't Fragment` bit set (Linux) to test different MTU sizes and identify potential issues."
    },
     {
        "id": 25,
        "question":"You are analyzing a suspicious email that you believe might be a phishing attempt. What are some KEY indicators that would suggest the email is NOT legitimate?",
        "options":[
          "The email is from a known sender.",
            "Poor grammar and spelling, a generic greeting (not personalized), a sense of urgency or threat, requests for sensitive information (passwords, credit card numbers), unexpected attachments, and links that don't match the displayed text (hover over links to see the actual URL) or go to unfamiliar domains.",
            "The email has a professional-looking design.",
            "The email is encrypted."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Phishing emails often contain clues that reveal their deceptive nature: poor grammar, generic greetings, a sense of urgency, requests for sensitive information, unexpected attachments, and suspicious links.  A known sender *can* be spoofed. A professional design *can* be faked. Encryption *itself* doesn't indicate legitimacy (phishing emails *can* even use HTTPS).",
        "examTip": "Be extremely cautious of emails that exhibit any of the common phishing indicators; when in doubt, *do not* click on links or open attachments, and verify the sender's authenticity through a *separate*, trusted channel (e.g., phone call, official website)."
    },
       Okay, continuing from question #26, here are the remaining questions for Test #8 (Very Challenging Difficulty):

{
        "id": 26,
        "question": "A user reports that their computer is running slowly.  You open Task Manager and see that a process named `dwm.exe` is using a significant amount of GPU resources. What is `dwm.exe` normally responsible for, and what could be causing the high GPU usage?",
        "options":[
            "`dwm.exe` is a web browser; the user probably has too many tabs open.",
            "`dwm.exe` (Desktop Window Manager) is a core Windows process responsible for compositing and displaying the graphical user interface (desktop, windows, visual effects). High GPU usage by `dwm.exe` could be caused by a faulty graphics driver, a demanding application (like a game or video editor), multiple high-resolution displays, or potentially malware.",
            "`dwm.exe` is a third-party application; you should uninstall it.",
            "`dwm.exe` is a virus; you should immediately delete it."
        ],
        "correctAnswerIndex": 1,
        "explanation": "`dwm.exe` (Desktop Window Manager) is a *critical* Windows process that handles the visual composition of the desktop. It's responsible for things like window transparency, animations, and 3D effects. High GPU usage by `dwm.exe` is *not* normal and can indicate a problem with the graphics driver, a demanding application that's using a lot of graphical resources, a misconfiguration (like multiple high-resolution displays pushing the GPU too hard), or, less commonly, malware. It's *not* a web browser, a third-party application (normally), or a virus *itself*.",
        "examTip": "High GPU usage by `dwm.exe` can indicate driver problems, demanding applications, or display configuration issues; investigate the graphics driver, running applications, and display settings."
    },
    {
        "id": 27,
        "question":"You are troubleshooting a network connectivity issue where a computer can access some websites but not others. `ping` tests to the affected websites' IP addresses are successful, but `ping <domain_name>` and `nslookup` both fail for those websites. However, you can successfully `ping` and `nslookup` *other* websites. What is the MOST likely cause?",
        "options":[
            "The user's computer has a faulty network cable.",
           "The DNS records for the *specific* affected websites are incorrect or missing on the DNS servers the user's computer is configured to use, *or* there's a selective DNS poisoning/hijacking attack in progress.",
            "The user's web browser is corrupted.",
            "The affected websites' servers are all down."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If *some* websites resolve correctly (both `ping` and `nslookup`) but *others* don't (while pings to the *IP addresses* of the affected sites *work*), the problem is almost certainly with the DNS records *for those specific websites* on the user's configured DNS servers. This could be due to incorrect DNS configuration, DNS server problems, or a *targeted* DNS poisoning/hijacking attack (where an attacker manipulates DNS responses to redirect traffic). A cable problem would likely cause more general issues. A browser problem is less likely to cause DNS resolution failures. It's extremely unlikely that *only* the affected websites' servers are down.",
        "examTip": "When troubleshooting inconsistent website access, carefully compare DNS resolution for working and non-working sites; discrepancies point to DNS record problems or potential DNS hijacking."
    },
     {
        "id": 28,
        "question": "You are using the `netstat` command in Windows. You want to display all active connections and listening ports, including the process ID (PID) associated with each connection, *and* you want the output to be displayed numerically (without resolving hostnames or port names to their symbolic representations). Which command would you use?",
        "options":[
          "netstat -a",
          "netstat -b",
          "netstat -ano",
          "netstat -o"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`netstat -ano` provides all the requested information: `-a` shows all connections and listening ports, `-n` displays addresses and ports numerically, and `-o` shows the owning process ID. `-b` shows the executable name (requires administrator privileges), but it doesn't force numerical output like `-n` does.",
        "examTip": "`netstat -ano` is a powerful command for network troubleshooting in Windows; it shows active connections, listening ports, and process IDs in a numerical format."
    },
    {
        "id":29,
        "question": "A user reports they are unable to connect to their corporate VPN.  They are working from home and can access the internet normally.  Other users are able to connect to the VPN successfully. What is the MOST likely cause on the *user's* end?",
        "options":[
          "The VPN server is down.",
            "A firewall on the user's home router is blocking the VPN connection, the VPN client software is misconfigured or not running, or there's a problem with the user's VPN credentials.",
            "The user's internet service provider (ISP) is experiencing an outage.",
            "The user's computer has a virus."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If *other* users can connect to the VPN, and the affected user has general internet access, the problem is most likely local to the *user's setup*. A firewall on their home router could be blocking the VPN ports or protocols, the VPN client software might be misconfigured (wrong server address, incorrect settings), not running, or the user's VPN credentials might be incorrect or expired. The VPN server being down or an ISP outage would affect *all* users. A virus *could* interfere, but the other factors are more directly related to VPN connectivity.",
        "examTip": "When troubleshooting VPN connection problems where other users are successful, focus on local factors: firewall, VPN client configuration, and credentials."
    },
     {
        "id": 30,
        "question": "You are troubleshooting a Windows computer that is experiencing frequent system crashes (BSODs).  You suspect a faulty device driver. You've already tried updating and rolling back drivers, with no success. What is the NEXT BEST tool to use to try to identify the specific driver causing the crashes?",
        "options":[
           "System Restore",
            "Windows Memory Diagnostic",
            "Driver Verifier (verifier.exe)",
            "Task Manager"
        ],
        "correctAnswerIndex": 2,
        "explanation": "Driver Verifier is a built-in Windows tool specifically designed to stress-test device drivers and identify those that are causing system instability. It puts extra pressure on drivers, making it more likely that a buggy driver will cause a crash (and hopefully, a memory dump that can be analyzed). System Restore might revert to a previous state, but doesn't *diagnose* the specific driver. Windows Memory Diagnostic tests RAM. Task Manager shows running processes.",
        "examTip": "Use Driver Verifier (`verifier.exe`) to help identify faulty drivers causing BSODs; be prepared for potential system instability while Driver Verifier is active, and have a way to disable it (e.g., Safe Mode)."
    },
    {
        "id": 31,
        "question": "You are using Wireshark to capture and analyze network traffic. You want to filter the displayed packets to show only traffic originating from a specific source IP address (e.g., 192.168.1.50). Which Wireshark display filter would you use?",
        "options":[
            "`ip.dst == 192.168.1.50`",
           "`ip.src == 192.168.1.50`",
            "`tcp.port == 80`",
            "`http`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`ip.src == 192.168.1.50` is the correct Wireshark display filter to show only packets where the *source* IP address is 192.168.1.50. `ip.dst` filters by *destination* IP address. `tcp.port` filters by TCP port number, and `http` filters for HTTP traffic.",
        "examTip": "Use `ip.src` and `ip.dst` in Wireshark display filters to isolate traffic based on source and destination IP addresses, respectively."
    },
    {
        "id": 32,
        "question": "You are configuring a Linux server and want to view the system's hardware information, including details about the CPU, memory, and connected devices. Which command provides a comprehensive overview of the system's hardware?",
        "options":[
          "top",
          "free -m",
          "lshw",
          "df -h"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`lshw` (list hardware) is a powerful tool that provides detailed information about the system's hardware configuration, including CPU, memory, disks, network interfaces, and more. `top` shows running processes, `free -m` shows memory usage, and `df -h` shows disk space usage.",
        "examTip": "Use `lshw` on Linux systems to gather detailed information about the system's hardware configuration."
      },
    {
        "id":33,
        "question": "What is 'vishing'?",
        "options":[
            "A type of malware that encrypts files.",
            "A type of social engineering attack that uses voice communication (phone calls) to trick victims into revealing sensitive information or performing actions that compromise security.",
            "A type of network attack that floods a server with traffic.",
            "A type of attack that exploits vulnerabilities in software."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Vishing (voice phishing) is a form of social engineering that uses phone calls to impersonate legitimate organizations or individuals and trick victims into divulging personal information, financial details, or credentials. It's not malware, a network flood, or a direct software exploit.",
        "examTip": "Be extremely cautious of unsolicited phone calls asking for personal information or requesting you to take actions on your computer; verify the caller's identity through a *separate*, trusted channel."
    },
     {
        "id": 34,
        "question": "A user reports that their Windows computer is displaying an error message stating that a specific DLL file is missing or corrupt. What is the BEST first step to attempt to resolve this issue?",
        "options":[
           "Reinstall the operating system.",
            "Run the System File Checker (`sfc /scannow`) to scan for and repair corrupted system files, including DLLs. If that doesn't work, try to identify which application the DLL belongs to and reinstall *that specific application*.",
            "Delete the DLL file.",
            "Download the DLL file from a random website on the internet."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Missing or corrupt DLL files can cause application errors. The System File Checker (`sfc /scannow`) is designed to scan for and repair corrupted *system* files, including DLLs. If `sfc` doesn't fix it, identifying the *application* that uses the DLL and reinstalling *that application* is often the next best step. Reinstalling the *entire OS* is too drastic. Deleting the DLL is likely to make things worse. Downloading DLLs from random websites is *extremely dangerous* and can lead to malware infection.",
        "examTip": "Use `sfc /scannow` to repair corrupted system files, including DLLs; if that fails, try reinstalling the specific application associated with the missing or corrupt DLL. *Never* download DLLs from untrusted websites."
    },
    {
        "id": 35,
        "question": "You are troubleshooting a network connectivity issue on a Linux server. You want to see the current status of all network interfaces, including their IP addresses, MAC addresses, and whether they are up or down. Which command is BEST suited for this task?",
        "options":[
            "netstat -r",
           "ip addr show (or the older `ifconfig` command, though `ip` is preferred on modern systems)",
            "route -n",
            "ping"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`ip addr show` (or the older `ifconfig` - though `ip` is preferred on modern Linux systems) displays detailed information about all network interfaces, including their IP addresses, MAC addresses, status (up/down), and other configuration details. `netstat -r` and `route -n` show the routing table. `ping` tests connectivity to a specific host.",
        "examTip": "Use `ip addr show` (or `ifconfig` on older systems) to view detailed network interface configuration on Linux."
    },
    {
        "id": 36,
        "question": "You are configuring a new computer with an SSD as the primary boot drive.  Which firmware setting (BIOS/UEFI) should you verify to ensure optimal performance and compatibility with the SSD?",
        "options":[
           "Enable Legacy Boot mode.",
            "Ensure AHCI (Advanced Host Controller Interface) or NVMe mode is selected for the SATA controller (or NVMe controller, if applicable), *not* IDE emulation mode.",
            "Disable the onboard graphics.",
            "Set the boot order to prioritize the network."
        ],
        "correctAnswerIndex": 1,
        "explanation": "AHCI (or NVMe for NVMe SSDs) is the modern interface for SATA (and NVMe) drives and provides features that improve SSD performance, such as Native Command Queuing (NCQ). IDE emulation mode is a legacy compatibility mode that can significantly limit SSD performance. Legacy Boot mode is related to the boot *process* (BIOS vs. UEFI), not the storage interface. Onboard graphics and boot order are unrelated.",
        "examTip": "Always use AHCI (or NVMe) mode for SSDs in the BIOS/UEFI settings for optimal performance; avoid IDE emulation mode."
    },
     {
        "id":37,
        "question": "What is 'whaling' in the context of social engineering attacks?",
        "options":[
           "A type of malware that encrypts files.",
            "A highly targeted phishing attack that focuses on high-profile individuals (executives, CEOs, etc.) within an organization.",
            "A type of network attack that floods a server with traffic.",
            "A type of attack that exploits vulnerabilities in software."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Whaling is a specific type of spear phishing that targets 'big fish' - high-value individuals within an organization, such as executives, who have access to sensitive information or financial resources.  It's not malware, a network flood, or a direct software exploit.",
        "examTip": "High-profile individuals should be particularly vigilant about phishing attempts; whaling attacks are highly targeted and often use sophisticated social engineering techniques."
    },
    {
        "id": 38,
        "question": "You are troubleshooting a website that is intermittently unavailable. You suspect a DNS problem. You've already used `nslookup` to query your default DNS server, and it *sometimes* fails to resolve the website's domain name. What is the NEXT BEST step to investigate?",
        "options":[
          "Reinstall your web browser.",
            "Use `nslookup` to query *different* DNS servers (e.g., Google Public DNS - 8.8.8.8, Cloudflare - 1.1.1.1) to see if the problem is specific to your default DNS server. Also, consider using `dig` (Domain Information Groper) on Linux/macOS for more detailed DNS queries.",
            "Restart your computer.",
            "Replace your network cable."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If `nslookup` is *intermittently* failing, testing with *different* DNS servers helps isolate the problem. If other DNS servers consistently resolve the domain name, the issue is likely with your *default* DNS server (or the network path to it). Reinstalling the browser is unlikely to help with DNS resolution. Restarting *might* temporarily help, but doesn't diagnose the root cause. A cable problem is less likely if *other* network functions are working. `dig` is a more powerful DNS lookup utility available on Linux/macOS (and can be installed on Windows).",
        "examTip": "When troubleshooting DNS problems, test with multiple DNS servers to determine if the issue is with your default DNS server or with the domain name's DNS records themselves."
    },
    {
        "id": 39,
        "question": "You are configuring a new server and want to ensure that all data on the hard drive is encrypted to protect against unauthorized access if the server is stolen or compromised. Which technology is BEST suited for this purpose?",
        "options":[
          "EFS (Encrypting File System)",
           "Full-disk encryption (e.g., BitLocker on Windows, LUKS on Linux, FileVault on macOS).",
            "VPN (Virtual Private Network)",
            "Firewall"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Full-disk encryption encrypts the *entire* hard drive, including the operating system and all data. This protects the data even if the server is physically stolen. EFS encrypts individual files and folders, but not the entire drive. A VPN encrypts network traffic, not the data at rest on the drive. A firewall controls network access, not data encryption.",
        "examTip": "Use full-disk encryption to protect all data on a server or laptop, especially if it contains sensitive information."
    },
    {
        "id": 40,
        "question":"You are analyzing a captured network traffic file (PCAP) using Wireshark. You want to see all the HTTP requests and responses. Which Wireshark display filter is the MOST efficient and accurate way to achieve this?",
        "options":[
           "`tcp.port == 80`",
            "`http`",
            "`ip.addr == 192.168.1.1`",
            "`tcp`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The display filter `http` in Wireshark is specifically designed to show all HTTP protocol traffic. While `tcp.port == 80` would *often* show HTTP traffic (as port 80 is the standard HTTP port), it wouldn't capture HTTP traffic on *other* ports, and it might include *non*-HTTP traffic that happens to use port 80. `ip.addr` filters by IP address, and `tcp` shows all TCP traffic.",
        "examTip": "Use protocol names (http, https, dns, ftp, smtp, etc.) directly as Wireshark display filters for the most accurate and efficient way to isolate traffic for specific protocols."
    },
     {
        "id": 41,
        "question":"You are investigating a security incident where a user's account has been compromised. You suspect that the attacker may have used the compromised account to access other systems on the network. Which log file on a *Windows* domain controller would be MOST helpful in identifying which systems the compromised account attempted to access?",
        "options": [
            "System Log",
            "Application Log",
           "Security Log on the domain controller, specifically looking for Kerberos authentication events and logon/logoff events related to the compromised account.",
            "Setup Log"
        ],
        "correctAnswerIndex": 2,
        "explanation":"In a Windows domain environment, the domain controllers handle user authentication (using the Kerberos protocol).  The Security Log on the *domain controllers* (not individual workstations) records Kerberos authentication events and logon/logoff events. By examining these logs, you can see which systems the compromised account attempted to access (successfully or unsuccessfully). The System and Application logs are less directly related to user authentication *across the domain*. The Setup log is for installation events.",
        "examTip":"In a Windows domain, examine the Security logs on the *domain controllers* to track user authentication and access attempts across the network."
    },
    {
        "id": 42,
        "question": "You are troubleshooting a computer that is experiencing frequent Blue Screen of Death (BSOD) errors. You have used Driver Verifier to stress-test drivers, and the system crashed with a specific bug check code. What is the NEXT step to analyze the crash and identify the potential cause?",
        "options":[
           "Reinstall the operating system.",
           "Analyze the memory dump file (.dmp) created during the BSOD using a debugging tool like WinDbg. The bug check code and the information in the memory dump can often pinpoint the faulty driver or hardware component.",
            "Run Disk Cleanup.",
            "Run System Restore."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Memory dump files generated during BSODs contain valuable diagnostic information. Analyzing the dump file with a debugging tool like WinDbg (part of the Windows SDK) allows you to examine the system state at the time of the crash, identify the specific error (bug check code), and often pinpoint the faulty driver or hardware component responsible. Reinstalling the OS is a last resort. Disk Cleanup and System Restore are less likely to provide specific diagnostic information about the *cause* of the BSOD.",
        "examTip": "Learn to use WinDbg (or a similar debugging tool) to analyze Windows memory dump files; this is a critical skill for troubleshooting BSODs and other system crashes."
    },
     {
        "id": 43,
        "question":"A user reports that their computer is running slowly, and they suspect a virus. You've run multiple antivirus and anti-malware scans, but they haven't detected anything. What is a *less common*, but still possible, type of malware that might be causing the problem, and how would you try to detect it?",
        "options":[
          "A boot sector virus; run a standard antivirus scan.",
            "A rootkit; use specialized rootkit detection tools (e.g., GMER, TDSSKiller, aswMBR) or a bootable antivirus rescue disk.",
            "A Trojan horse; look for unusual running processes in Task Manager.",
            "Spyware; check the browser's homepage and search engine settings."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Rootkits are designed to hide themselves from standard antivirus scans and operating system tools. They often operate at a very low level (kernel mode) and can intercept system calls to conceal their presence. Specialized rootkit detection tools and bootable rescue disks are needed to detect and remove them. While the *other options* describe *types* of malware, rootkits are specifically designed to be *stealthy* and evade standard detection.",
        "examTip": "If you suspect a malware infection, but standard scans are clean, consider the possibility of a rootkit and use specialized rootkit detection tools."
    },
     {
        "id": 44,
        "question": "You are configuring a web server to use HTTPS. You've obtained an SSL/TLS certificate from a Certificate Authority (CA) and installed it on the server. However, when you try to access the website using `https://`, you get a certificate error in your browser. What is a *likely* cause, *assuming the certificate itself is valid*?",
        "options":[
           "The website's URL is not using 'https://'.",
            "The web server software (e.g., IIS, Apache) is not properly configured to use the certificate for HTTPS connections, the certificate is not bound to the correct website/virtual host, the certificate's common name (CN) or Subject Alternative Name (SAN) doesn't match the website's domain name, or there's a problem with the certificate chain of trust.",
            "The user's computer does not have the correct date and time.",
            "The user's web browser is outdated."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Certificate errors, *assuming the certificate itself is valid*, often indicate a problem with the *server's configuration* or a mismatch between the certificate and the website. The web server software needs to be explicitly configured to use the certificate for HTTPS. The certificate must be *bound* to the correct website/virtual host. The certificate's *Common Name (CN)* or *Subject Alternative Name (SAN)* must match the website's domain name.  Also, the browser must trust the *certificate chain* (the CA that issued the certificate, and any intermediate CAs). While an incorrect date/time *can* cause certificate errors, it's less likely than a server configuration issue. An outdated browser *might* have problems, but a server configuration issue is more probable.",
        "examTip": "When troubleshooting HTTPS certificate errors, carefully check the server's configuration (certificate installation and binding), the certificate's details (CN, SAN, expiration date), and the certificate chain of trust."
    },
     {
        "id": 45,
        "question":"You are troubleshooting a network connectivity issue on a Linux server. You suspect a problem with the routing table. Which command would you use to display the *kernel's* IP routing table?",
        "options":[
           "ifconfig",
            "ip addr show",
            "`route -n` (or `ip route show`)",
            "netstat -i"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`route -n` (or the newer `ip route show`) displays the kernel's IP routing table, showing how network traffic will be routed to different destinations. `ifconfig` and `ip addr show` display interface configuration. `netstat -i` shows interface statistics.",
        "examTip": "Use `route -n` (or `ip route show`) on Linux to view the kernel's IP routing table and understand how network traffic is being routed."
    },
    {
        "id": 46,
        "question":"You are troubleshooting a network connectivity issue. A computer can access some websites but not others.  `ping` tests to the IP addresses of the affected websites are successful, but `ping <domain_name>` and `nslookup` fail for those specific websites.  You've already verified that *other* computers on the same network *can* access those websites. What is the MOST likely cause on the *affected* computer?",
        "options": [
            "The user's network cable is faulty."
            "The user's network card is faulty",
           "There's an entry in the Windows 'hosts' file that is overriding DNS resolution for the affected websites, redirecting them to an incorrect IP address or blocking them entirely.",
            "The user's DNS server is misconfigured."
        ],
        "correctAnswerIndex": 2,
        "explanation": "If *other* computers on the *same network* can access the websites, and you can *ping the correct IP addresses* from the affected computer, the problem is almost certainly *local* to that computer and related to *name resolution*. The Windows 'hosts' file is a likely culprit. Entries in the 'hosts' file take precedence over DNS resolution.  A faulty cable or network card would likely cause more general connectivity problems. The DNS server configuration is *unlikely* to be the issue if *other* computers on the same network are working and if you can ping the *correct* IP address.",
        "examTip": "The Windows 'hosts' file can override DNS resolution; check it for incorrect or malicious entries when troubleshooting website access problems where basic connectivity and DNS *should* be working."
    },
    {
        "id": 47,
        "question": "You are investigating a potential security incident on a Windows server. You need to determine which user accounts have logged on to the server interactively (locally or via Remote Desktop) over the past week. Which Windows Event Log, and which specific event IDs, would you examine?",
        "options":[
            "System Log; Event ID 1149",
           "Security Log; Event IDs 4624 (logon) and 4634/4647 (logoff).",
            "Application Log; Event ID 1000",
            "Setup Log; Event ID 1"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The *Security* Log in Event Viewer records security-related events, including logon and logoff activity. Event ID 4624 indicates a successful logon, and Event IDs 4634 and 4647 indicate logoff events. You would need to filter the Security Log for these specific event IDs and the relevant time period to see the logon/logoff history. The System, Application, and Setup logs are not the primary logs for tracking user logon activity.",
        "examTip": "Learn to use the Windows Event Viewer and understand key event IDs (like 4624 and 4634/4647 for logon/logoff) for security auditing and troubleshooting."
    },
    {
        "id": 48,
        "question": "You are configuring a Linux server and want to restrict network access to specific services based on the source IP address. You decide to use `iptables`. Which table and chain within `iptables` would you typically use to create *filtering* rules that allow or deny incoming connections?",
        "options":[
           "mangle table, PREROUTING chain",
            "filter table, INPUT chain",
            "nat table, POSTROUTING chain",
            "raw table, OUTPUT chain"
        ],
        "correctAnswerIndex": 1,
        "explanation": "The `filter` table in `iptables` is used for *filtering* network traffic (allowing or denying connections). The `INPUT` chain within the `filter` table is used to control *incoming* connections to the server. The `mangle` table is for modifying packet headers, the `nat` table is for Network Address Translation, and the `raw` table is for very early packet processing (before connection tracking).",
        "examTip": "Understand the different tables and chains in `iptables`: `filter` for filtering, `nat` for NAT, `mangle` for packet modification. Use the `INPUT` chain for incoming traffic, `OUTPUT` for outgoing traffic, and `FORWARD` for traffic passing *through* the system."
    },
     {
        "id": 49,
        "question":"A user reports that their Windows computer is very slow to start up. You've already disabled unnecessary startup programs in Task Manager and msconfig, and you've run a full system scan with antivirus software (which found nothing). What is the NEXT BEST tool to use for a detailed analysis of the boot process, potentially identifying a specific driver or service causing the slowdown?",
        "options":[
            "Disk Cleanup",
           "Windows Performance Recorder (WPR) and Windows Performance Analyzer (WPA), part of the Windows Assessment and Deployment Kit (ADK).",
            "System Restore",
            "Event Viewer"
        ],
        "correctAnswerIndex": 1,
        "explanation": "WPR/WPA provides *extremely* detailed performance tracing and analysis capabilities. It can capture a trace of the entire boot process and then allows you to analyze that trace, identifying which drivers, services, and processes are taking the longest to load. This level of detail is often necessary to pinpoint the cause of slow boot times. Disk Cleanup removes files. System Restore might revert to a previous state, but doesn't *diagnose* the specific cause. Event Viewer *might* contain clues, but WPR/WPA is the *direct* performance analysis tool.",
        "examTip": "Learn to use Windows Performance Recorder (WPR) and Windows Performance Analyzer (WPA) for in-depth analysis of boot performance and other performance issues in Windows."
    },
    {
        "id": 50,
        "question": "You are troubleshooting a network connectivity issue where a computer can access some websites but not others. Pings to the IP addresses of *all* websites (both working and non-working) are successful. `nslookup` *also* resolves all domain names correctly. What is a *less common*, but still possible, cause you should investigate?",
        "options":[
           "The user's network cable is faulty.",
            "The user's web browser is corrupted.",
            "A problem with MTU (Maximum Transmission Unit) settings, causing larger packets to be dropped or fragmented, *or* a problem with PMTUD (Path MTU Discovery).",
            "The user's DNS server is misconfigured."
        ],
        "correctAnswerIndex": 2,
        "explanation": "If *all* pings by IP and `nslookup` are successful, basic connectivity and DNS resolution are working.  A *less common*, but still possible, cause of selective website access problems is an MTU issue.  If the MTU is set too high for a particular network path, larger packets might be fragmented or dropped, causing some websites (that rely on larger packets) to fail while others (using smaller packets) work. A faulty cable or corrupted browser would likely cause more general problems. DNS is already ruled out.",
        "examTip": "MTU mismatches can cause subtle and selective network connectivity problems; use `ping` with the `-l` (Windows) or `-s` (Linux) option and the Don't Fragment bit set to test different MTU sizes and troubleshoot MTU-related issues."
    },
     {
            "id":51,
            "question": "You are using `tcpdump` on a Linux server to capture network traffic for analysis.  You want to capture all traffic *to or from* a specific IP address (e.g., 192.168.1.100) and save the captured packets to a file named `capture.pcap`. Which command would you use?",
            "options":[
                "`tcpdump -i any host 192.168.1.100`",
               "`tcpdump -i any host 192.168.1.100 -w capture.pcap`",
                "`tcpdump -i any port 80 -w capture.pcap`",
                "`tcpdump -i any -w capture.pcap`"
            ],
            "correctAnswerIndex": 1,
            "explanation": "`tcpdump -i any host 192.168.1.100 -w capture.pcap` is the correct command. `-i any` captures traffic on all interfaces. `host 192.168.1.100` filters for traffic to or from the specified IP address. `-w capture.pcap` saves the captured packets to the file `capture.pcap`. Option A doesn't save to a file. Option C captures traffic on port 80, not a specific host. Option D captures *all* traffic, not just traffic to/from the specified IP.",
            "examTip": "Learn the basic `tcpdump` syntax: `-i` for interface, `host`, `net`, `port` for filtering, and `-w` to save captured packets to a file."
        },
            {
        "id": 52,
        "question":"What is 'pass-the-hash' attack?",
        "options":[
            "A type of phishing attack.",
           "An attack where the attacker captures a user's password hash (rather than the plaintext password) and uses that hash directly to authenticate to a system or service, without needing to crack the password.",
            "A type of denial-of-service attack.",
            "A type of malware that encrypts files."
        ],
        "correctAnswerIndex": 1,
        "explanation": "In a pass-the-hash attack, the attacker doesn't need the *plaintext* password. They steal the *hashed* version of the password (e.g., from a compromised system or network traffic) and then use that hash *directly* to authenticate to a system or service that accepts hashed credentials. This bypasses the need to crack the password. It's not phishing (though phishing *could* be used to *obtain* the hash), a DoS attack, or malware that encrypts files.",
        "examTip": "Pass-the-hash attacks are a serious threat, especially in Windows environments; mitigation strategies include using strong, unique passwords, enabling multi-factor authentication, and implementing security measures to prevent credential theft."
    },
    {
        "id": 53,
        "question":"You are troubleshooting a Windows computer that is experiencing intermittent system crashes. You suspect a problem with a device driver. You've already updated and rolled back drivers, and used Driver Verifier, but the problem persists. What is a MORE ADVANCED technique you can use to try to isolate the faulty driver?",
        "options":[
           "Reinstall the operating system.",
            "Use the Windows Debugging Tools (WinDbg) to analyze memory dump files created during the crashes, looking for clues about the specific driver or component causing the problem. This often requires analyzing stack traces and understanding kernel-mode debugging.",
            "Run Disk Cleanup.",
            "Run System Restore."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Analyzing memory dump files with WinDbg is the most advanced and often the most effective way to diagnose the root cause of system crashes, especially when driver problems are suspected. This requires specialized knowledge of debugging techniques, but it can provide very specific information about the faulty driver or hardware component. Reinstalling the OS is a last resort. Disk Cleanup and System Restore are less likely to provide the *specific diagnostic information* needed.",
        "examTip": "Learning to use WinDbg to analyze memory dumps is a valuable skill for advanced Windows troubleshooting; it can help pinpoint the cause of crashes that are difficult to diagnose otherwise."
    },
     {
        "id": 54,
        "question": "A user reports that they are unable to access a specific network share. You've verified the following: the user has the correct permissions, the file server is online and accessible to other users, DNS resolution is working correctly, the user can ping the file server by IP address and hostname, and there are no apparent firewall rules blocking access. What is a *less common*, but still possible, cause related to the *Server Message Block (SMB)* protocol that you should investigate?",
        "options":[
            "The user's network cable is faulty.",
           "A mismatch in SMB signing settings or SMB protocol version compatibility between the client and server.",
            "The user's account is locked out.",
            "The file server is out of disk space."
        ],
        "correctAnswerIndex": 1,
        "explanation": "SMB signing is a security feature that helps prevent man-in-the-middle attacks. If there's a mismatch in SMB signing settings (e.g., the server *requires* signing, but the client doesn't support it, or vice versa), it can prevent access to network shares, *even if* all other factors (permissions, connectivity, DNS) are correct.  Also, older clients might only support SMBv1, while newer servers might disable it for security reasons. A cable problem would likely cause more general connectivity issues. An account lockout usually prevents *login*, not access after successful login. Server disk space would likely affect *all* users.",
        "examTip": "Be aware of SMB signing and SMB protocol version compatibility issues, especially in mixed Windows environments with older and newer systems; these can cause unexpected access problems to network shares."
    },
    {
        "id": 55,
        "question": "You are troubleshooting a website that is loading slowly.  Using the browser's developer tools (Network tab), you notice that several JavaScript and CSS files are taking a long time to download.  What are some potential optimization techniques that could improve the loading time of these resources?",
        "options":[
          "Increase the size of the images on the website.",
            "Minify the JavaScript and CSS files (remove unnecessary whitespace and comments), combine multiple files into fewer files (to reduce the number of HTTP requests), enable HTTP compression (e.g., gzip) on the web server, and use a Content Delivery Network (CDN).",
            "Disable browser caching.",
            "Use a slower DNS server."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Several techniques can optimize JavaScript and CSS delivery: *Minification* reduces file size by removing unnecessary characters. *Combining files* reduces the number of HTTP requests (which adds overhead). *HTTP compression* (like gzip) reduces the amount of data transferred. A *CDN* (Content Delivery Network) caches content closer to users, reducing latency. Increasing image size would *worsen* performance. Disabling caching would *force* the browser to download resources every time, slowing down performance. A slower DNS server would affect *initial* connection time, but not the download of individual files.",
        "examTip": "Optimize website performance by minifying and combining JavaScript/CSS files, enabling HTTP compression, and using a CDN to deliver static assets efficiently."
    },
    {
        "id": 56,
        "question": "You are investigating a potential security incident and need to analyze a Windows memory dump file. Which tool is BEST suited for this task?",
        "options":[
           "Task Manager",
            "Resource Monitor",
            "WinDbg (Windows Debugger)",
            "Event Viewer"
        ],
        "correctAnswerIndex": 2,
        "explanation": "WinDbg (part of the Windows SDK) is a powerful debugger that can be used to analyze memory dump files created during system crashes (BSODs) or other events. It allows you to examine the system's state at the time of the crash, including loaded drivers, running processes, and memory contents. Task Manager and Resource Monitor are for real-time monitoring. Event Viewer shows system logs, but doesn't provide the level of detail needed for memory dump analysis.",
        "examTip": "Learn to use WinDbg for analyzing Windows memory dump files; it's a critical skill for advanced troubleshooting and security incident response."
    },
    {
        "id": 57,
        "question":"You are using the `tcpdump` command on a Linux server to capture network traffic. You want to capture all traffic *destined for* port 80 (HTTP) and save the captured packets to a file named `http_traffic.pcap`. Which command would you use?",
        "options":[
           "`tcpdump -i any host 192.168.1.1 -w http_traffic.pcap`",
            "`tcpdump -i any port 80 -w http_traffic.pcap`",
            "`tcpdump -i any src port 80 -w http_traffic.pcap`",
            "`tcpdump -i any -w http_traffic.pcap`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`tcpdump -i any port 80 -w http_traffic.pcap` is the correct command. `-i any` captures traffic on all interfaces. `port 80` filters for traffic *to or from* port 80 (you could also use `dst port 80` to be *more specific* about the *destination* port). `-w http_traffic.pcap` saves the captured packets to the file `http_traffic.pcap`. Option A filters by host, not port. Option C filters by *source* port (which is usually a random high port, not 80). Option D captures *all* traffic.",
        "examTip": "Use `tcpdump` with the `port` filter to capture traffic to or from a specific port number; use `src port` or `dst port` to be more specific about the source or destination port."
    },
    {
        "id":58,
        "question": "You are configuring a new server with multiple network interfaces. You want to combine two of these interfaces into a single logical interface for increased bandwidth and redundancy. What is this technique called, and what are some common implementations?",
        "options":[
           "VLAN tagging",
           "NIC teaming (also known as bonding or link aggregation); common implementations include LACP (Link Aggregation Control Protocol) and static link aggregation.",
            "Port mirroring",
            "Spanning Tree Protocol"
        ],
        "correctAnswerIndex": 1,
        "explanation": "NIC teaming (or bonding/link aggregation) combines multiple physical network interfaces into a single logical interface. This can increase bandwidth (by aggregating the capacity of the interfaces) and provide redundancy (if one interface fails, the others continue to function). LACP (802.3ad) is a standard protocol for dynamically configuring link aggregation. VLAN tagging is for separating network traffic, port mirroring is for copying traffic for monitoring, and Spanning Tree Protocol is for preventing loops in switched networks.",
        "examTip": "Use NIC teaming (bonding) to increase network bandwidth and provide redundancy for servers or critical network devices."
    },
     {
        "id":59,
        "question":"A user reports that they are unable to access a specific website. You suspect a DNS problem. You've already tried `ping <domain_name>` (which failed) and `ipconfig /flushdns`. You then use `nslookup` to query *multiple different* DNS servers (including the user's configured DNS server and public DNS servers like 8.8.8.8).  `nslookup` *fails* to resolve the domain name with *all* tested DNS servers. What does this indicate?",
        "options":[
            "The user's computer has a faulty network cable.",
            "The user's web browser is corrupted.",
           "The problem is likely with the *domain name's DNS records themselves* (they might be incorrect, missing, or the domain name might not be registered or have expired), or there's a widespread DNS outage affecting multiple DNS servers.",
            "The website's server is down."
        ],
        "correctAnswerIndex": 2,
        "explanation": "If `nslookup` fails to resolve the domain name with *multiple, independent* DNS servers, the problem is almost certainly with the *domain name's DNS records* or a widespread DNS outage. It's highly unlikely that *multiple* DNS servers would be simultaneously misconfigured for the *same* domain. A cable problem or browser issue wouldn't cause *system-wide* DNS resolution failures with *multiple* servers. While the *website's server* being down is *possible*, the fact that `nslookup` fails with *multiple servers* points to a DNS problem *before* even reaching the website's server.",
        "examTip": "If `nslookup` fails with *multiple, independent* DNS servers, the problem is likely with the domain name's DNS records or a widespread DNS outage; it's *not* just a problem with your local DNS configuration."
    },
    {
        "id": 60,
        "question":"What is 'privilege escalation' in the context of cybersecurity?",
        "options":[
            "A type of social engineering attack.",
           "An attack where a user or process gains higher-level privileges than they are authorized to have, potentially allowing them to access sensitive data or perform unauthorized actions.",
            "A type of denial-of-service attack.",
            "A type of malware that encrypts files."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Privilege escalation is a critical security vulnerability. Attackers exploit bugs, misconfigurations, or vulnerabilities to gain *higher* privileges than they should have.  For example, a standard user might gain administrator privileges, or a process running with limited rights might gain system-level access. It's not social engineering *directly* (though social engineering *could* be used to *facilitate* privilege escalation), a DoS attack, or malware that encrypts files.",
        "examTip": "Prevent privilege escalation by following the principle of least privilege, keeping software up-to-date (to patch vulnerabilities), and implementing strong security configurations."
    },
    {
        "id": 61,
        "question": "You are troubleshooting a Windows computer and suspect that a particular program is causing system instability.  You want to prevent this program from running temporarily *without* uninstalling it.  Which of the following methods is the LEAST disruptive and MOST easily reversible?",
        "options":[
          "Delete the program's executable file.",
          "Rename the program's executable file.",
            "Use the System Configuration utility (msconfig.exe) to disable the program's startup entry (if it starts automatically), or use Task Manager to end the process (if it's currently running), or, if it's a service, use the Services console (services.msc) to stop and disable the service.",
            "Reinstall the operating system."
        ],
        "correctAnswerIndex": 2,
        "explanation": "Using `msconfig` (for startup programs), Task Manager (for running processes), or the Services console (for services) allows you to *temporarily* disable the program without making permanent changes.  This is easily reversible. Deleting or renaming the executable file is drastic, potentially damaging the program's installation and making it difficult to restore. Reinstalling the OS is a last resort.",
        "examTip": "Use standard Windows tools (msconfig, Task Manager, Services console) to temporarily disable programs for troubleshooting purposes; avoid deleting or renaming files unless you are absolutely sure it's safe and necessary."
    },
    {
        "id": 62,
        "question": "You are working with a Linux system and need to determine the amount of free and used memory (RAM). Which command provides this information in a human-readable format?",
        "options":[
           "top",
            "free -m",
            "vmstat",
            "df -h"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`free -m` displays the amount of free and used physical memory (RAM) and swap space on the system. The `-m` option shows the values in megabytes (you can also use `-g` for gigabytes or `-h` for a more automatically-scaled human-readable format). `top` shows running processes and overall system resource usage (including memory, but `free` is more direct). `vmstat` provides more detailed virtual memory statistics. `df -h` shows *disk* space usage, not memory.",
        "examTip": "Use `free -m` (or `free -h`) on Linux to quickly check memory usage."
    },
    {
        "id": 63,
        "question":"What is the purpose of a 'reverse proxy' in a network configuration?",
        "options":[
           "To provide a secure connection for remote access to a private network.",
            "To act as an intermediary between clients and servers, forwarding client requests to the appropriate backend server (often used for load balancing, security, and caching).",
            "To encrypt network traffic.",
            "To filter network traffic based on IP addresses and ports."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A reverse proxy sits *in front of* one or more servers and handles requests from clients. It can provide several benefits: *Load balancing:* distributing client requests across multiple servers. *Security:* hiding the internal server structure and potentially filtering malicious requests. *Caching:* storing frequently accessed content to improve performance. *SSL encryption/decryption:* offloading the processing of SSL/TLS from the web servers. It's *not* primarily for secure remote access (VPNs do that), general encryption (though it *can* handle SSL/TLS), or basic filtering (firewalls do that).",
        "examTip": "Reverse proxies are commonly used to improve web server performance, security, and scalability; they act as an intermediary between clients and backend servers."
    },
    {
        "id": 64,
        "question": "A user reports that their Windows computer is displaying an error message stating, 'The application was unable to start correctly (0xc000007b).' What is a LIKELY cause of this error, and how would you troubleshoot it?",
        "options":[
          "The computer's hard drive is full.",
            "A problem with the application's dependencies (e.g., missing or corrupted DLL files), a conflict between 32-bit and 64-bit versions of DLLs, or potentially a problem with the .NET Framework. Try reinstalling the application, running `sfc /scannow`, checking for and installing any required dependencies (like Visual C++ Redistributables), or repairing/reinstalling the .NET Framework.",
            "The user's network connection is unstable.",
            "The user's account does not have administrator privileges."
        ],
        "correctAnswerIndex": 1,
        "explanation": "The error code 0xc000007b (STATUS_INVALID_IMAGE_FORMAT) often indicates a problem with DLL files – either missing, corrupted, or a mismatch between 32-bit and 64-bit versions. It can also be related to problems with the .NET Framework.  A full hard drive, unstable network, or lack of administrator privileges are *less likely* to cause this *specific* error code. Reinstalling the *application*, running `sfc /scannow`, checking dependencies, and repairing/reinstalling .NET Framework are the most relevant troubleshooting steps.",
        "examTip": "The Windows error code 0xc000007b often indicates a problem with DLL files or the .NET Framework; troubleshoot application dependencies and system files."
    },
    {
        "id": 65,
        "question":"You are analyzing a PCAP file with Wireshark and need to isolate all traffic related to DNS (Domain Name System) queries and responses. Which Wireshark display filter is the MOST efficient and accurate way to achieve this?",
        "options":[
           "`tcp.port == 53`",
            "`udp.port == 53`",
            "`dns`",
            "`ip.addr == 8.8.8.8`"
        ],
        "correctAnswerIndex": 2,
        "explanation": "The display filter `dns` in Wireshark is specifically designed to show all DNS protocol traffic. While DNS primarily uses UDP port 53, it *can* also use TCP port 53 (for larger responses or zone transfers). Using `dns` as the filter captures *both* UDP and TCP DNS traffic. `tcp.port == 53` would only show TCP traffic on port 53, and `udp.port == 53` would only show UDP traffic. `ip.addr` filters by IP address, not protocol.",
        "examTip": "Use protocol names (like `dns`, `http`, `ssh`, etc.) directly as Wireshark display filters to efficiently isolate traffic for specific protocols."
    },
    {
        "id": 66,
        "question": "You are working on a Linux system and need to find all files owned by a specific user (e.g., 'john'). Which command would you use?",
        "options":[
           "`grep john /etc/passwd`",
            "`find / -user john`",
            "`locate john`",
            "`ls -l | grep john`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`find / -user john` is the correct command. `find` is used to locate files. `/` specifies the root directory (search the entire system). `-user john` specifies that you're looking for files owned by the user 'john'. `grep` searches *within* files, `locate` uses a pre-built database (which might be outdated), and `ls -l` lists files in a directory (and would only show files in the *current* directory, not recursively).",
        "examTip": "Use the `find` command with the `-user` option to locate files owned by a specific user on a Linux system."
    },
    {
        "id": 67,
        "question": "You are troubleshooting a website that is intermittently unavailable. You suspect a problem with the web server itself. Which of the following tools or techniques would be MOST helpful in determining if the web server is experiencing resource constraints (high CPU, memory, or disk I/O) that might be causing the intermittent outages?",
        "options":[
           "`ping` the website's domain name.",
            "Use `nslookup` to check DNS resolution.",
            "Remotely connect to the web server (if possible) and use system monitoring tools (e.g., Task Manager on Windows, `top` or `htop` on Linux, Resource Monitor) to check resource utilization.  Also, examine the web server's logs (e.g., IIS logs, Apache logs) for errors.",
            "Run a virus scan on your computer."
        ],
        "correctAnswerIndex": 2,
        "explanation": "If you suspect a problem with the *web server itself*, you need to *monitor the server's resources*. Remotely connecting to the server (if you have access) and using system monitoring tools (Task Manager, `top`, `htop`, Resource Monitor) allows you to see real-time CPU, memory, and disk I/O usage.  Also, examining the *web server's logs* (IIS logs, Apache logs, Nginx logs) can reveal errors or performance issues. `ping` and `nslookup` test *network connectivity* and DNS resolution, not server resource usage. A virus scan on *your* computer is irrelevant.",
        "examTip": "When troubleshooting web server problems, monitor the server's resource utilization (CPU, memory, disk I/O) and examine the web server's logs for errors."
    },
    {
        "id": 68,
        "question": "A user reports that their computer is displaying a 'PXE-E61: Media test failure, check cable' error message during startup. What does this indicate?",
        "options":[
            "The computer's hard drive has failed.",
           "The computer is attempting to boot from the network (using PXE - Preboot Execution Environment), but it's failing to connect to the network or find a boot server.",
            "The computer's RAM is faulty.",
            "The computer's video card is not working."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A PXE-E61 error indicates a problem with *network booting*. The computer is trying to boot from a network server using PXE, but it's either failing to connect to the network (check the cable and network connection) or it can't find a valid PXE boot server. It's not a hard drive failure *directly* (though it *could* be that the system is *trying* to PXE boot because it *can't* find a bootable hard drive), RAM, or video card issue.",
        "examTip": "PXE boot errors indicate a problem with network booting; check network connectivity, PXE server availability, and the BIOS/UEFI boot order settings."
    },
    {
        "id": 69,
        "question": "You are configuring a new computer and want to ensure that the system clock is always accurate. You decide to use NTP (Network Time Protocol) for time synchronization. Which port does NTP typically use?",
        "options":[
           "22",
            "53",
            "80",
            "123"
        ],
        "correctAnswerIndex": 3,
        "explanation": "NTP uses UDP port 123. Port 22 is for SSH, 53 is for DNS, and 80 is for HTTP.",
        "examTip": "NTP uses UDP port 123 for time synchronization; ensure this port is open on firewalls if you're using an external NTP server."
    },
     {
        "id": 70,
        "question": "You are troubleshooting a Windows computer that is experiencing frequent application crashes. You suspect a problem with the .NET Framework. Where would you typically find information about .NET Framework errors and potentially diagnose the issue?",
        "options":[
          "Task Manager",
          "Resource Monitor",
            "Event Viewer (specifically the Application log, and potentially the System log), and consider using the .NET Framework Repair Tool.",
            "Device Manager"
        ],
        "correctAnswerIndex": 2,
        "explanation": ".NET Framework errors often appear in the Application log in Event Viewer. The System log might also contain related errors. The .NET Framework Repair Tool (available from Microsoft) can sometimes fix problems with the .NET Framework installation. Task Manager and Resource Monitor show running processes and resource usage, but not detailed error logs. Device Manager is for hardware devices.",
        "examTip": "Check the Application log in Event Viewer for .NET Framework errors when troubleshooting application crashes; the .NET Framework Repair Tool can also be helpful."
    },
    {
        "id": 71,
        "question":"You are using the `ping` command to troubleshoot network connectivity. You want to send larger packets than the default size to test for potential MTU (Maximum Transmission Unit) issues. Which option would you use with the `ping` command in *Windows*?",
        "options":[
           "-t",
            "-l <size>",
            "-n <count>",
            "-f"
        ],
        "correctAnswerIndex": 1,
        "explanation": "In Windows, the `-l` option (lowercase L) with `ping` specifies the *size* (in bytes) of the ICMP echo request packet to send. This allows you to test with larger packets. `-t` pings continuously, `-n` specifies the number of pings, and `-f` sets the Don't Fragment flag (useful for MTU troubleshooting, but *in addition to* `-l`).",
        "examTip": "Use `ping -l <size>` in Windows to send larger ICMP echo request packets for testing MTU or network performance."
    },
     {
        "id": 72,
        "question": "You are troubleshooting a slow website. Using the browser's developer tools (Network tab), you identify a specific resource (e.g., an image, a JavaScript file, a CSS file) that is taking a long time to download. Besides optimizing the resource itself (e.g., compressing images), what is a network-level technique that can *significantly* improve the delivery speed of static assets?",
        "options":[
           "Increasing the website's DNS TTL (Time to Live).",
            "Using a Content Delivery Network (CDN) to cache and serve the static assets from servers geographically closer to the users.",
            "Disabling browser caching.",
            "Using a slower DNS server."
        ],
        "correctAnswerIndex": 1,
        "explanation": "A CDN (Content Delivery Network) is a distributed network of servers that caches static content (images, JavaScript, CSS, etc.) closer to users. This reduces latency and improves download speeds, as users retrieve the content from a nearby server instead of the origin server. Increasing DNS TTL affects how long DNS records are cached, but not the *delivery* of the content itself. Disabling caching would *worsen* performance. A slower DNS server would affect initial connection time, but not file download speed *after* the connection is established.",
        "examTip": "Use a CDN (Content Delivery Network) to improve website performance by caching static assets closer to users, reducing latency and improving download speeds."
    },
    {
        "id": 73,
        "question": "You are working with a Linux system and need to view the last few lines of a very large log file. Which command is BEST suited for this task?",
        "options":[
           "cat",
            "more",
            "less",
            "tail"
        ],
        "correctAnswerIndex": 3,
        "explanation": "`tail` is specifically designed to display the *last* part of a file (by default, the last 10 lines). This is ideal for viewing the end of log files. `cat` displays the *entire* file, `more` and `less` are pagers that allow you to scroll through the file, but they start at the *beginning*. `tail` is the most efficient for viewing the *end*.",
        "examTip": "Use `tail` on Linux to view the last few lines of a file (especially useful for log files); you can use `tail -n <number>` to specify the number of lines to display, or `tail -f` to follow the file in real-time as new lines are added."
    },
     {
        "id": 74,
        "question":"You are configuring a firewall and need to allow inbound connections to a specific service running on your server. However, you only want to allow connections from a specific, trusted IP address. What type of firewall rule would you create?",
        "options":[
           "An outbound rule.",
            "An inbound rule that specifies the allowed source IP address, the destination IP address (your server), the destination port (the service's port), and the protocol (e.g., TCP or UDP).",
            "A port forwarding rule.",
            "A DMZ rule."
        ],
        "correctAnswerIndex": 1,
        "explanation": "To allow *inbound* connections *selectively*, you need an *inbound* firewall rule. This rule should specify: the *source IP address* (the allowed client), the *destination IP address* (your server), the *destination port* (the port the service is listening on), and the *protocol* (TCP or UDP). This restricts access to only the specified source IP. An outbound rule controls traffic *leaving* your server. Port forwarding is a type of inbound rule, but it's typically used to redirect traffic from a public IP/port to a private IP/port (behind a NAT router). A DMZ is a separate network segment.",
        "examTip": "Firewall rules can filter traffic based on source IP address, destination IP address, port, and protocol; use these criteria to create precise rules that allow only necessary traffic."
    },
     {
        "id": 75,
        "question": "What is 'cryptojacking'?",
        "options":[
           "A type of social engineering attack.",
            "The unauthorized use of someone else's computer resources to mine cryptocurrency, often without their knowledge or consent.",
            "A type of attack that exploits vulnerabilities in software.",
            "A type of denial-of-service attack."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Cryptojacking involves secretly using someone else's computer (or server) to mine cryptocurrency. Attackers install malware or use malicious scripts on websites to hijack the victim's processing power, slowing down their system and potentially increasing their electricity costs. It's not social engineering *directly* (though it can be *spread* through social engineering), a software exploit *directly* (though it *can* exploit vulnerabilities), or a DoS attack.",
        "examTip": "Cryptojacking can be difficult to detect; monitor your system's resource usage (CPU, GPU) for unexplained spikes, and use security software that can detect cryptomining malware."
    },
        {
            "id":76,
            "question": "Which type of attack attempts to crack passwords by systematically trying every possible combination of characters?",
            "options": [
                "Dictionary attack",
               "Brute-force attack",
                "Rainbow table attack",
                "Phishing attack"
            ],
            "correctAnswerIndex": 1,
            "explanation": "A brute-force attack tries *every possible combination* of characters (letters, numbers, symbols) until the correct password is found. This can be very time-consuming, especially for long and complex passwords. A dictionary attack tries words from a dictionary. A rainbow table attack uses precomputed hashes. Phishing is social engineering.",
            "examTip": "Strong, long, and complex passwords are the best defense against brute-force attacks; account lockout policies can also help mitigate this type of attack."
        },
         {
            "id": 77,
            "question": "You are troubleshooting a slow Windows computer. You open Task Manager and see that the disk utilization is consistently at 100%, but no single process appears to be responsible for all of the activity. The computer has an HDD. What is the BEST tool to use to get a more detailed view of *which files* are being accessed and contributing to the high disk I/O?",
            "options":[
               "Task Manager",
                "Resource Monitor (specifically the Disk tab)",
                "Performance Monitor",
                "Disk Defragmenter"
            ],
            "correctAnswerIndex": 1,
            "explanation": "Resource Monitor's Disk tab provides detailed information about disk I/O activity, including the *specific files* being read from and written to, and the processes accessing them. This allows you to pinpoint the source of the high disk utilization. Task Manager shows overall disk usage, but not file-level details. Performance Monitor can track disk activity over time, but Resource Monitor is better for *real-time* analysis of specific files. Disk Defragmenter optimizes file layout (and shouldn't be used on SSDs).",
            "examTip": "Use Resource Monitor's Disk tab to diagnose high disk I/O and identify the specific files and processes responsible."
        },
         {
            "id": 78,
            "question":"You are working on a Linux system and need to find all files that were modified within the last 24 hours. Which command would you use?",
            "options":[
               "`grep -r 'modified' /`",
                "`find / -mtime -1`",
                "`locate modified`",
                "`ls -l | grep 'today'`"
            ],
            "correctAnswerIndex": 1,
            "explanation": "`find / -mtime -1` is the correct command. `find` is used to locate files. `/` specifies the root directory (search the entire system). `-mtime -1` finds files modified less than 1 day ago (within the last 24 hours). `grep` searches *within* files, `locate` uses a pre-built database (which might be outdated), and `ls -l` lists files in a directory (and wouldn't search recursively).",
            "examTip": "Use the `find` command with the `-mtime` option to locate files based on their modification time in Linux."
        },
        {
            "id": 79,
            "question": "What is the purpose of using a 'honeypot' in a network security context?",
            "options":[
               "To encrypt sensitive data.",
                "To filter network traffic and block malicious connections.",
                "To act as a decoy system, attracting attackers and allowing security professionals to study their methods, gather intelligence, and potentially divert them from real targets.",
                "To provide a secure remote access connection."
            ],
            "correctAnswerIndex": 2,
            "explanation": "A honeypot is a deliberately vulnerable system designed to attract attackers. It's a trap, allowing security researchers to observe attack techniques, collect information about attackers, and potentially distract them from attacking real, valuable systems. It's not for encryption, general traffic filtering (firewalls do that), or secure remote access (VPNs do that).",
            "examTip": "Honeypots are used for threat research and deception; they can provide valuable insights into attacker behavior, but they should be carefully deployed and monitored."
        },
           {
        "id": 80,
        "question": "You are configuring a new server and want to ensure that the system clock is automatically and accurately synchronized with a reliable time source. Which protocol is BEST suited for this, and what is its standard port number?",
        "options":[
           "FTP; port 21",
            "NTP (Network Time Protocol); port 123",
            "HTTP; port 80",
            "SMTP; port 25"
        ],
        "correctAnswerIndex": 1,
        "explanation": "NTP (Network Time Protocol) is specifically designed for time synchronization across a network. It uses UDP port 123. FTP is for file transfer, HTTP is for web browsing, and SMTP is for email.",
        "examTip": "Configure your systems (especially servers) to synchronize with a reliable NTP server (either a public server or an internal one) to ensure accurate timekeeping, which is crucial for logging, security, and many applications."
    },
    {
        "id":81,
        "question": "You are troubleshooting a website that is intermittently slow or unavailable. You suspect a problem with the website's DNS records. Which command-line tool (available on most operating systems) provides the MOST comprehensive and detailed information about a domain's DNS records, including different record types (A, AAAA, MX, CNAME, TXT, etc.)?",
        "options":[
            "ping",
            "nslookup",
           "dig (Domain Information Groper)",
            "tracert"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`dig` is a powerful and flexible DNS lookup utility that provides much more detailed information than `nslookup` or `ping`. It allows you to query specific DNS servers, retrieve different record types (A, AAAA, MX, CNAME, TXT, SOA, etc.), and examine the complete DNS response. `ping` tests basic connectivity, `nslookup` is a simpler DNS lookup tool, and `tracert` traces network routes.",
        "examTip": "Learn to use `dig` for advanced DNS troubleshooting and querying; it provides much more detailed information than `nslookup`."
    },
     {
        "id": 82,
        "question":"What is 'data masking' in the context of data security and privacy?",
        "options":[
          "Encrypting data to protect it from unauthorized access.",
            "Replacing sensitive data with non-sensitive substitute values (e.g., replacing real credit card numbers with fake numbers) while preserving the data's format and usability for testing or development purposes.",
            "Backing up data to a secure location.",
            "Deleting data permanently."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Data masking (or data obfuscation) is a technique for protecting sensitive data while still allowing it to be used for non-production purposes (like testing, development, or analytics).  Real data values are replaced with realistic but *fake* values, preserving the data's format and usability without exposing the actual sensitive information.  It's not encryption *itself* (though masking can be *combined* with encryption), backup, or deletion.",
        "examTip": "Use data masking techniques to protect sensitive data in non-production environments (testing, development, analytics); this reduces the risk of data breaches and helps comply with privacy regulations."
    },
    {
        "id": 83,
        "question": "You are troubleshooting a Windows computer that is experiencing frequent application crashes. You suspect a problem with the .NET Framework. Which Windows tool is specifically designed to help diagnose and repair .NET Framework installations?",
        "options":[
          "System File Checker (sfc /scannow)",
            "The Microsoft .NET Framework Repair Tool (available for download from Microsoft).",
            "Disk Cleanup",
            "Resource Monitor"
        ],
        "correctAnswerIndex": 1,
        "explanation": "Microsoft provides a dedicated .NET Framework Repair Tool that can diagnose and fix common issues with .NET Framework installations. While `sfc /scannow` can repair *system* files, the .NET Framework Repair Tool is *specifically* targeted at .NET Framework problems. Disk Cleanup removes files, and Resource Monitor shows resource usage.",
        "examTip": "If you suspect problems with the .NET Framework in Windows, download and run the Microsoft .NET Framework Repair Tool."
    },
    {
        "id": 84,
        "question": "You are configuring a Linux server and need to set up a firewall to control network access. You decide to use `iptables`. You want to create a rule that allows incoming SSH connections (on port 22) *only from* a specific IP address (192.168.1.100). Which `iptables` command would you use?",
        "options":[
          "`iptables -A INPUT -p tcp --dport 22 -j ACCEPT`",
            "`iptables -A INPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT`",
            "`iptables -A OUTPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT`",
            "`iptables -A FORWARD -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`iptables -A INPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT` is the correct command. `-A INPUT` appends the rule to the `INPUT` chain (for incoming traffic). `-p tcp` specifies the TCP protocol. `--dport 22` specifies the destination port (22 for SSH). `-s 192.168.1.100` specifies the *source* IP address (the allowed client). `-j ACCEPT` specifies the action (accept the connection). Option A allows *all* SSH connections. Option C is for *outgoing* traffic. Option D is for traffic passing *through* the server (not destined *for* the server).",
        "examTip": "Understand the structure of `iptables` rules: `-A` (append), `-I` (insert), `-D` (delete), table (`filter`, `nat`, `mangle`, `raw`), chain (`INPUT`, `OUTPUT`, `FORWARD`), matching criteria (`-p`, `--dport`, `--sport`, `-s`, `-d`), and target (`ACCEPT`, `DROP`, `REJECT`)."
    },
    {
        "id": 85,
        "question": "You are troubleshooting a network connectivity issue where a computer can access some websites but not others.  Pings to the IP addresses of *all* websites (both working and non-working) are successful.  `nslookup` *also* resolves all domain names correctly. You've checked the 'hosts' file, firewall rules, and proxy settings, and they all appear to be correct. What is a *less common*, but still possible, cause that you should investigate?",
        "options":[
          "The user's network cable is faulty.",
            "A problem with MTU (Maximum Transmission Unit) settings or Path MTU Discovery, causing larger packets to be dropped or fragmented, *or* an issue with TCP window scaling.",
            "The user's web browser is corrupted.",
            "The user's DNS server is misconfigured."
        ],
        "correctAnswerIndex": 1,
        "explanation": "If *all* pings by IP and `nslookup` are successful, and you've ruled out common local issues (hosts file, firewall, proxy), a *less common* but still possible cause is an MTU problem. If the MTU is set too high for a particular network path, larger packets might be dropped or fragmented, causing some websites (that rely on larger packets) to fail while others work. TCP window scaling issues can *also* cause similar problems.  A faulty cable or corrupted browser would likely cause more general problems. DNS is already ruled out.",
        "examTip": "MTU mismatches and TCP window scaling problems can cause subtle and selective network connectivity issues; use `ping` with the `-l` (Windows) or `-s` (Linux) option and the Don't Fragment bit set to test different MTU sizes."
    },
	{
        "id": 86,
        "question": "You are investigating a potential security incident on a Linux server. You want to see a list of all successful and failed login attempts. Which log file should you examine?",
        "options":[
           "`/var/log/messages`",
            "`/var/log/auth.log` (or `/var/log/secure` on some systems like Red Hat/CentOS)",
            "`/var/log/syslog`",
            "`/var/log/dmesg`"
        ],
        "correctAnswerIndex": 1,
        "explanation": "`/var/log/auth.log` (or `/var/log/secure` on some distributions) is the primary log file for authentication-related events on most Linux systems. It records successful and failed login attempts, SSH logins, sudo usage, and other authentication-related activity. `/var/log/messages` and `/var/log/syslog` are general system logs. `/var/log/dmesg` shows kernel messages.",
        "examTip": "Examine `/var/log/auth.log` (or `/var/log/secure`) on Linux systems to audit login attempts and identify potential security breaches."
    },
    {
        "id": 87,
        "question": "You are using the `tcpdump` command to capture network traffic. You want to capture all traffic *to or from* a specific host (IP address 192.168.1.50) *and* a specific port (port 80). Which `tcpdump` command would you use?",
        "options":[
           "`tcpdump -i any host 192.168.1.50`",
            "`tcpdump -i any port 80`",
            "`tcpdump -i any host 192.168.1.50 and port 80`",
            "`tcpdump -i any host 192.168.1.50 or port 80`"
        ],
        "correctAnswerIndex": 2,
        "explanation": "`tcpdump -i any host 192.168.1.50 and port 80` is the correct command. `-i any` captures traffic on all interfaces. `host 192.168.1.50` filters for traffic to or from the specified IP address. `port 80` filters for traffic to or from port 80. The `and` keyword combines these two filters, so the command captures only traffic that matches *both* conditions. Option A only filters by host. Option B only filters by port. Option D uses `or`, which would capture traffic to/from *either* the host *or* the port (not necessarily *both*).",
        "examTip": "Use logical operators (`and`, `or`, `not`) in `tcpdump` expressions to create complex filters that match specific criteria."
    },
    {
       "id": 88,
       "question":"A user reports that they are unable to access a specific network share. You have verified the user's permissions, network connectivity, DNS resolution and the status of the SMB service on both ends. All other users can access this share successfully. What is a *very specific*, but often overlooked setting to check on the *user's* Windows computer?",
       "options":[
        "Check the user's network cable",
        "Restart the file server.",
        "Check the 'Credential Manager' on the user's Windows computer for any stored credentials related to the file server that might be incorrect or outdated. Delete any cached credentials for the server and try reconnecting.",
        "Reinstall the user's network adapter driver."
       ],
       "correctAnswerIndex": 2,
       "explanation":"Windows Credential Manager stores usernames and passwords for network resources. If the user has *previously* saved incorrect credentials for the file server, Windows might be trying to use those outdated credentials, even if the user *thinks* they are entering the correct password. Deleting any cached credentials for the server in Credential Manager forces Windows to prompt for the password again, potentially resolving the issue. A cable or driver problem would likely cause more general issues. Restarting the *server* is unnecessary if *other* users can connect.",
       "examTip":"Check the Windows Credential Manager for outdated or incorrect stored credentials when troubleshooting network share access problems, especially if the user has previously accessed the share."
    },
     {
        "id": 89,
        "question": "You are troubleshooting a Windows computer that is experiencing intermittent system freezes. You've already checked for overheating, run Windows Memory Diagnostic (no errors), and run a full system scan with antivirus software (no threats found). You suspect a hardware problem. Besides the motherboard and hard drive, which other component is a frequent cause of *intermittent* freezes and should be tested?",
        "options":[
            "The keyboard.",
           "The power supply unit (PSU). A failing or underpowered PSU can cause intermittent instability, even if the system doesn't shut down completely.",
            "The monitor.",
            "The network cable."
        ],
        "correctAnswerIndex": 1,
        "explanation": "Intermittent freezes (not complete shutdowns) can be caused by a failing or underpowered PSU that's not providing *consistent* power to the system. While a completely dead PSU would prevent booting, a *weak* or *failing* PSU can cause instability. The keyboard, monitor, and network cable are *much* less likely to cause *system freezes*.",
        "examTip": "Don't overlook the power supply unit (PSU) when troubleshooting intermittent system freezes or instability; a failing or underpowered PSU can cause a variety of problems."
    },
    {
        "id": 90,
        "question": "You are configuring a Linux server to act as a router (forwarding traffic between two network interfaces). You've configured the IP addresses on the interfaces, but traffic is not being forwarded. What is a likely cause, and how would you enable IP forwarding?",
        "options":[
           "The firewall is blocking traffic.",
            "IP forwarding is disabled by default in the Linux kernel; enable it by setting the `net.ipv4.ip_forward` kernel parameter to 1 (e.g., using `sysctl -w net.ipv4.ip_forward=1` and making the change permanent in `/etc/sysctl.conf`).",
            "The routing table is misconfigured.",
            "The network interfaces are down."
        ],
        "correctAnswerIndex": 1,
        "explanation": "IP forwarding (the ability of a system to act as a router, forwarding packets between networks) is *disabled* by default in the Linux kernel for security reasons. To enable it, you need to set the `net.ipv4.ip_forward` kernel parameter to 1.  `sysctl -w net.ipv4.ip_forward=1` enables it *temporarily*.  To make the change *permanent*, you need to add `net.ipv4.ip_forward = 1` to `/etc/sysctl.conf`. While a firewall *could* block traffic, IP forwarding must be *enabled* first.  A misconfigured routing table would affect *where* traffic is routed, but not *whether* forwarding happens at all. Down interfaces would prevent *all* traffic on those interfaces.",
        "examTip": "To enable IP forwarding on a Linux system (to make it act as a router), set the `net.ipv4.ip_forward` kernel parameter to 1 (using `sysctl` and editing `/etc/sysctl.conf` for persistence)."
    },
        {
            "id":91,
            "question": "You are attempting to troubleshoot a network issue using `ping`, but the remote host does not respond. You know the host is up and running. You suspect a firewall is blocking ICMP echo requests. What is an alternative tool/technique you can use to test basic connectivity to the remote host, assuming you know a specific TCP port (e.g., port 80 for a web server) that *should* be open on the target?",
            "options": [
                "Use `tracert`",
                "Use `nslookup`",
               "Use `telnet <remote_host> <port_number>` (e.g., `telnet example.com 80`) or `nc -zv <remote_host> <port_number>` (netcat) to attempt a TCP connection to the specific port. If the connection succeeds, you know basic connectivity is working, even if ICMP is blocked.",
                "Use `ipconfig /flushdns`"
            ],
            "correctAnswerIndex": 2,
            "explanation": "If ICMP (ping) is blocked, but you know a specific TCP port *should* be open on the remote host, you can use `telnet` (though it's an insecure protocol, it can still be used for *basic connectivity testing*) or `nc` (netcat - a more versatile tool) to attempt a TCP connection to that port. If the connection succeeds, it confirms basic network reachability, even if ping is blocked. `tracert` relies on ICMP (and UDP on some systems), so it might also be blocked. `nslookup` is for DNS resolution. `ipconfig /flushdns` clears the local DNS cache.",
            "examTip": "If `ping` is blocked, use `telnet <host> <port>` or `nc -zv <host> <port>` to test TCP connectivity to a specific port on a remote host."

        },
         {
            "id": 92,
            "question":"What is 'shoulder surfing'?",
            "options":[
               "A type of phishing attack.",
                "Visually observing someone's screen or keyboard to steal their passwords, PINs, or other sensitive information.",
                "A type of denial-of-service attack.",
                "A type of malware."
            ],
            "correctAnswerIndex": 1,
            "explanation": "Shoulder surfing is a low-tech but effective social engineering technique where an attacker observes a user's screen or keyboard to steal sensitive information. It's not a phishing attack (though it *could* be used in conjunction with one), a DoS attack, or malware *itself*.",
            "examTip": "Be aware of your surroundings when entering passwords or viewing sensitive information, especially in public places, to prevent shoulder surfing."
        },
        {
            "id": 93,
            "question":"A user reports that their computer is exhibiting unusual behavior, including slow performance, unexpected pop-ups, and changes to their browser's homepage. You suspect malware, but standard antivirus and anti-malware scans are not detecting anything. You decide to use a bootable antivirus rescue disk. Why is this approach often MORE effective than running scans from within the infected operating system?",
            "options":[
                "Bootable rescue disks are faster.",
               "Bootable rescue disks operate *outside* the potentially compromised operating system, allowing them to detect and remove rootkits and other advanced malware that might be actively hiding from scans run *within* Windows.",
                "Bootable rescue disks have more up-to-date virus definitions.",
                "Bootable rescue disks can repair the operating system."
            ],
            "correctAnswerIndex": 1,
            "explanation": "The key advantage of a bootable rescue disk is that it runs in its own, independent environment, *before* the potentially infected operating system loads. This allows it to bypass any rootkits or other malware that might be actively hiding from scans run *within* the OS. While speed and updated definitions *can* be factors, the *independent operating environment* is the primary reason for its effectiveness against advanced threats.",
            "examTip": "Use a bootable antivirus rescue disk (from a reputable vendor) for thorough malware removal, especially when dealing with persistent or advanced threats that evade standard scans."
        },
        {
           "id":94,
           "question": "What is a 'watering hole' attack?",
           "options":[
                "Sending phishing emails to a large number of recipients.",
               "Compromising a website that is frequently visited by a specific target group (e.g., employees of a particular company, members of an organization) and infecting that website with malware, in order to infect the visitors' computers.",
                "Exploiting a vulnerability in a web server directly.",
                "Guessing user passwords."
           ],
           "correctAnswerIndex": 1,
           "explanation": "A watering hole attack is a targeted attack that focuses on a specific group of users. Attackers compromise a website that the target group is known to visit (like a watering hole that animals frequent). When members of the target group visit the compromised website, their computers are infected with malware. It's not generic phishing, a direct server exploit (though the website *itself* is compromised), or password guessing.",
           "examTip": "Watering hole attacks are sophisticated and exploit the trust users have in legitimate websites; keep your software up-to-date and be cautious about visiting unfamiliar sites, even if they seem relevant to your interests or work."
        },
        {
            "id": 95,
            "question":"You suspect that a particular Windows service is causing system instability. You want to prevent this service from starting automatically when Windows boots, but you don't want to uninstall the associated application. How can you achieve this?",
            "options":[
               "Delete the service's executable file.",
                "Use the Services console (services.msc) to change the service's startup type to 'Disabled' or 'Manual'.",
                "Rename the service in Task Manager.",
                "Use System Restore to revert to a previous state."
            ],
            "correctAnswerIndex": 1,
            "explanation": "The Services console (`services.msc`) provides a central interface for managing Windows services. You can change a service's startup type to: *Automatic* (starts automatically at boot), *Automatic (Delayed Start)* (starts shortly after boot), *Manual* (starts only when explicitly started by a user or another program), or *Disabled* (prevented from starting).  Deleting the executable is dangerous and could break the application. Renaming in Task Manager doesn't affect services. System Restore is a broader solution.",
            "examTip": "Use the Services console (`services.msc`) to manage Windows services, including changing their startup type to troubleshoot problems or optimize system performance."
        },
{
    "id": 96,
    "question": "You are troubleshooting a network issue and you use the ping command with a large packet size. Some packets go through, some don't. What could be the issue",
    "options":[
        "The DNS is down",
        "The remote host is down",
        "The network cable is unplugged.",
       "There is an MTU issue somewhere along the path."
    ],
    "correctAnswerIndex": 3,
    "explanation": "If some pings with a large packet size fail, but smaller ones do not there is likely an MTU issue. The other options would have total failure, not intermittent based on size.",
    "examTip": "MTU issues can be diagnosed with various ping sizes."
},
{
    "id": 97,
    "question": "A user is reporting issues connecting to the internet. They have a static IP address, what command can you use to check their settings in windows, and what setting specifically should you check?",
    "options":[
       "ipconfig, default gateway",
       "ifconfig, dns server",
       "ipconfig /all, default gateway",
       "ping, default gateway"
    ],
    "correctAnswerIndex": 2,
    "explanation": "The command `ipconfig /all` will give you all current TCP/IP configuration values. Including, but not limited too; Host, IP, DNS Servers, Default Gateway. Checking the default gateway will help ensure the user is communicating with the correct device to connect to the internet.",
    "examTip": "Use `ipconfig /all` to check multiple settings to diagnose a network issue."
},
{
    "id": 98,
    "question": "A technician is tasked with cleaning up a chemical spill in the server room, which document should they refer to?",
    "options":[
       "SOP",
       "AUP",
       "MSDS",
       "SLA"
    ],
    "correctAnswerIndex": 2,
    "explanation": "The Material Safety Data Sheet (MSDS) contains all details for chemicals, how to handle them, clean them, and dispose of them.",
    "examTip": "MSDS should be referenced for all chemical spills."
},
{
    "id":99,
    "question": "What is the primary purpose of using scheduled tasks in Windows?",
    "options": [
        "To monitor system performance in real-time.",
       "To automate the execution of programs or scripts at specific times or in response to specific events.",
        "To manage user accounts and permissions.",
        "To configure network settings."
    ],
    "correctAnswerIndex": 1,
    "explanation": "Scheduled Tasks allow you to automate routine tasks, such as running backups, scripts, or programs, without manual intervention. They are configured to run at specific times, on a recurring schedule, or in response to system events (like user logon or system startup). They are not for real-time performance monitoring, user account management, or network configuration *directly*.",
    "examTip": "Use Scheduled Tasks in Windows to automate routine tasks and improve system efficiency."
},
{
    "id": 100,
    "question": "You are using `tcpdump` on a Linux system to capture network traffic. You only want to capture traffic that is related to the SSH protocol. Which of the following `tcpdump` commands is the MOST efficient and accurate way to achieve this?",
    "options":[
       "`tcpdump -i any host 192.168.1.1`",
        "`tcpdump -i any port 22`",
        "`tcpdump -i any port 80`",
        "`tcpdump -i any`"
    ],
    "correctAnswerIndex": 1,
    "explanation": "`tcpdump -i any port 22` is the correct command. `-i any` specifies that `tcpdump` should capture traffic on *all* network interfaces. `port 22` filters the captured traffic to show only packets to or from port 22, which is the standard port for SSH. Option A filters by host, not protocol. Option C filters for HTTP traffic (port 80). Option D captures *all* traffic.",
    "examTip": "Use `tcpdump -i any port <port_number>` to capture traffic related to a specific protocol based on its standard port number (e.g., 22 for SSH, 80 for HTTP, 443 for HTTPS)."
}
]
}
