db.tests.insertOne({
  "category": "serverplus",
  "testId": 4,
  "testName": "CompTIA Server+ (SK0-005) Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A server with dual power supplies experiences intermittent shutdowns despite both PSUs being connected. What is the most likely issue?",
      "options": [
        "Both PSUs are connected to the same circuit",
        "The server’s BIOS is overriding redundancy settings",
        "The PSUs have mismatched firmware versions",
        "The cooling fans are causing voltage drops"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Connecting both PSUs to the same circuit undermines redundancy; if that circuit fails or is overloaded, both PSUs lose power, causing shutdowns. BIOS settings might affect detection, firmware mismatches could cause errors, and fans don’t typically drop voltage enough to shut down a server.",
      "examTip": "Ensure redundant PSUs use separate circuits to avoid single-point failures."
    },
    {
      "id": 2,
      "question": "Which RAID configuration offers the best write performance for a database server while maintaining fault tolerance?",
      "options": [
        "RAID 5 with a hardware controller",
        "RAID 6 with write-back caching",
        "RAID 10 with SSDs",
        "RAID 1 with a software controller"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 10 combines striping and mirroring, delivering superior write performance with fault tolerance, especially with SSDs. RAID 5 and 6 suffer from parity calculation overhead, and software RAID 1 lacks hardware acceleration.",
      "examTip": "RAID 10 shines for performance-critical apps like databases—speed and safety."
    },
    {
      "id": 3,
      "question": "A technician notices a server’s SSD performance degrades over time. What factor is most likely responsible?",
      "options": [
        "High read-intensive workloads",
        "Wear from excessive write operations",
        "Insufficient RAID parity updates",
        "Overheating due to poor ventilation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SSDs degrade due to wear from write operations, as flash memory cells have limited write cycles. Read-intensive loads don’t wear SSDs, RAID parity isn’t a factor here, and overheating affects function, not gradual degradation.",
      "examTip": "Monitor SSD write endurance for long-term performance planning."
    },
    {
      "id": 4,
      "question": "Which network configuration ensures uninterrupted connectivity if a single switch fails in a server rack?",
      "options": [
        "NIC teaming with failover",
        "Single NIC with VLAN tagging",
        "Round-robin load balancing",
        "Static IP assignment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIC teaming with failover links multiple NICs to different switches, ensuring connectivity if one switch fails. VLAN tagging organizes traffic, round-robin balances load, and static IPs don’t address hardware failure.",
      "examTip": "NIC teaming boosts network resilience—key for high availability."
    },
    {
      "id": 5,
      "question": "During a server audit, you find sensitive data unencrypted on a SAN. Which mitigation directly secures this data at rest?",
      "options": [
        "Enable SAN Fibre Channel zoning",
        "Implement AES-256 encryption on the drives",
        "Restrict SAN access with VLANs",
        "Deploy multifactor authentication for admins"
      ],
      "correctAnswerIndex": 1,
      "explanation": "AES-256 encryption secures data at rest on the SAN drives, making it unreadable without keys. Zoning and VLANs control access, and MFA secures admin logins, but only encryption protects the data itself.",
      "examTip": "Encryption is the ultimate safeguard for data at rest—prioritize it."
    },
    {
      "id": 6,
      "question": "A server running multiple VMs experiences high CPU utilization. What should be adjusted first to alleviate this?",
      "options": [
        "Increase VM memory allocation",
        "Reduce CPU overcommitment ratio",
        "Upgrade to faster SSD storage",
        "Add a second physical NIC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reducing CPU overcommitment limits the number of vCPUs assigned, easing the physical CPU load. Memory, storage, and NICs address different bottlenecks, not CPU overuse.",
      "examTip": "Overcommitted CPUs slow everything—balance resource allocation."
    },
    {
      "id": 7,
      "question": "Which backup strategy minimizes RPO for a critical server with frequent data changes?",
      "options": [
        "Daily full backups",
        "Hourly incremental backups",
        "Weekly differential backups",
        "Nightly synthetic full backups"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hourly incremental backups reduce the Recovery Point Objective (RPO) by capturing changes frequently, minimizing potential data loss. Full, differential, and synthetic backups have larger gaps between captures.",
      "examTip": "Frequent backups shrink RPO—time matters for critical data."
    },
    {
      "id": 8,
      "question": "A server’s BIOS fails to detect a new RAID controller. What should you check first?",
      "options": [
        "RAID controller firmware version",
        "BIOS boot order settings",
        "PCIe slot compatibility",
        "RAID array configuration"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PCIe slot compatibility (e.g., version, lane width) ensures the RAID controller is recognized by the BIOS. Firmware mismatches, boot order, and array config come after hardware detection.",
      "examTip": "Hardware recognition starts with physical compatibility—check the slot first."
    },
    {
      "id": 9,
      "question": "Which physical security measure most effectively prevents unauthorized access to a server rack during maintenance?",
      "options": [
        "CCTV monitoring with motion alerts",
        "Biometric locks on the rack door",
        "RFID badge entry to the data center",
        "Security guards at the facility entrance"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Biometric locks on the rack door provide direct, immediate access control during maintenance. CCTV monitors, RFID controls entry, and guards oversee the facility, but only biometrics secure the rack itself.",
      "examTip": "Layered security is key, but focus on the closest control point."
    },
    {
      "id": 10,
      "question": "A server’s network latency spikes during peak hours. What should you investigate first?",
      "options": [
        "CPU utilization on the server",
        "Network switch port saturation",
        "RAID controller cache settings",
        "Storage IOPS limits"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Network switch port saturation during peak hours can bottleneck traffic, increasing latency. CPU, RAID, and storage affect internal performance, not network latency directly.",
      "examTip": "Network issues often stem from infrastructure—start with the switch."
    },
    {
      "id": 11,
      "question": "Which file system supports snapshots and data integrity checks for a Linux server?",
      "options": [
        "NTFS",
        "ext4",
        "ZFS",
        "ReFS"
      ],
      "correctAnswerIndex": 2,
      "explanation": "ZFS offers snapshots and built-in data integrity checks, ideal for Linux. NTFS and ReFS are Windows-focused, and ext4 lacks native snapshot support.",
      "examTip": "ZFS stands out for advanced features—know its strengths."
    },
    {
      "id": 12,
      "question": "A server fails to boot after a power outage, displaying a CMOS error. What should you replace?",
      "options": [
        "RAID controller battery",
        "System RAM modules",
        "CMOS battery",
        "Power supply unit"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A CMOS error after a power outage indicates a failed CMOS battery, which maintains BIOS settings. RAID batteries, RAM, and PSUs don’t store CMOS data.",
      "examTip": "CMOS errors point to the battery—quick fix for boot issues."
    },
    {
      "id": 13,
      "question": "Which high-availability feature ensures automatic failover between two servers?",
      "options": [
        "Load balancing with round-robin",
        "Active-passive clustering",
        "NIC teaming with aggregation",
        "RAID 5 parity"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Active-passive clustering automatically fails over to a standby server if the primary fails. Load balancing distributes traffic, NIC teaming enhances networking, and RAID protects storage.",
      "examTip": "Clustering ensures uptime—active-passive is failover-ready."
    },
    {
      "id": 14,
      "question": "A server’s iSCSI SAN connection drops intermittently. What should you check first?",
      "options": [
        "RAID controller firmware",
        "Network switch jumbo frame settings",
        "SAN disk array health",
        "Server BIOS settings"
      ],
      "correctAnswerIndex": 1,
      "explanation": "iSCSI relies on network stability; misconfigured jumbo frames on the switch can cause drops. RAID firmware, SAN health, and BIOS are secondary checks for this network issue.",
      "examTip": "iSCSI issues often trace back to network config—start there."
    },
    {
      "id": 15,
      "question": "Which disaster recovery site type requires the longest setup time after a failure?",
      "options": [
        "Hot site",
        "Warm site",
        "Cold site",
        "Cloud site"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A cold site has minimal pre-configured equipment, requiring significant setup time post-failure. Hot sites are ready instantly, warm sites need some setup, and cloud sites vary but are typically faster.",
      "examTip": "Cold sites are cheap but slow—know recovery tradeoffs."
    },
    {
      "id": 16,
      "question": "A server’s application hangs, but the OS remains responsive. Where should you look first for clues?",
      "options": [
        "System event logs",
        "Application event logs",
        "BIOS error codes",
        "Network switch logs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Application event logs record app-specific issues like crashes or hangs. System logs cover OS/hardware, BIOS codes indicate boot errors, and switch logs track networking.",
      "examTip": "Application hangs mean app logs first—target the problem source."
    },
    {
      "id": 17,
      "question": "Which storage interface supports higher bandwidth and is commonly used in enterprise SANs?",
      "options": [
        "SATA",
        "SAS",
        "Fibre Channel",
        "USB"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Fibre Channel provides high bandwidth and low latency, making it standard for enterprise SANs. SATA and SAS are for local drives, and USB is external, not SAN-suited.",
      "examTip": "Fibre Channel rules SANs—high speed for enterprise needs."
    },
    {
      "id": 18,
      "question": "A server’s NIC fails, but connectivity persists. What configuration is likely in place?",
      "options": [
        "VLAN tagging on a single NIC",
        "NIC teaming with failover",
        "Static routing tables",
        "Bridged virtual networking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NIC teaming with failover switches to a backup NIC if one fails, maintaining connectivity. VLANs, routing, and bridging don’t provide this redundancy.",
      "examTip": "Failover in NIC teaming keeps you connected—redundancy rules."
    },
    {
      "id": 19,
      "question": "Which scripting language is native to Windows for automating server administration tasks?",
      "options": [
        "Bash",
        "Python",
        "PowerShell",
        "Perl"
      ],
      "correctAnswerIndex": 2,
      "explanation": "PowerShell is Microsoft’s native scripting language for Windows automation. Bash is Linux-based, Python and Perl are cross-platform but not native to Windows.",
      "examTip": "PowerShell is Windows’ automation king—learn its commands."
    },
    {
      "id": 20,
      "question": "A server’s RAID 5 array reports slow write performance. What is the most likely cause?",
      "options": [
        "Insufficient CPU resources",
        "Parity calculation overhead",
        "Overloaded network bandwidth",
        "Faulty RAID controller battery"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 5’s parity calculations slow write performance due to additional processing. CPU, network, and battery issues affect other aspects, not write speed directly.",
      "examTip": "RAID 5 trades write speed for redundancy—parity is the culprit."
    },
    {
      "id": 21,
      "question": "Which security practice ensures only necessary ports are open on a server?",
      "options": [
        "Applying OS patches",
        "Configuring firewall rules",
        "Using strong passwords",
        "Enabling MFA"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firewall rules restrict open ports to only what’s needed, reducing the attack surface. Patching, passwords, and MFA enhance security but don’t control ports.",
      "examTip": "Firewalls lock down ports—tighten them up."
    },
    {
      "id": 22,
      "question": "A server’s memory errors cause random crashes. What should you do first?",
      "options": [
        "Update the BIOS firmware",
        "Reseat the RAM modules",
        "Increase swap space",
        "Replace the CPU"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reseating RAM modules fixes loose connections, a common cause of memory errors. BIOS updates, swap space, and CPU replacement are less immediate solutions.",
      "examTip": "Memory issues? Reseat first—simple fixes save time."
    },
    {
      "id": 23,
      "question": "Which virtualization networking mode assigns VMs their own IP addresses on the physical network?",
      "options": [
        "NAT",
        "Bridged",
        "Host-only",
        "Internal"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Bridged mode connects VMs directly to the physical network, assigning unique IPs. NAT shares the host’s IP, host-only isolates VMs, and internal limits to VM-to-VM.",
      "examTip": "Bridged VMs act like physical devices—full network integration."
    },
    {
      "id": 24,
      "question": "A server’s backup fails due to insufficient space. What should you adjust?",
      "options": [
        "Increase RAID array capacity",
        "Reduce backup retention period",
        "Upgrade network bandwidth",
        "Add more VM CPU cores"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reducing the retention period frees up space by deleting older backups. RAID capacity adds storage, but retention directly addresses space usage; bandwidth and CPU are unrelated.",
      "examTip": "Backup space issues? Trim retention—quick and effective."
    },
    {
      "id": 25,
      "question": "Which command verifies network connectivity to a remote server?",
      "options": [
        "ipconfig",
        "netstat",
        "ping",
        "tracert"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Ping tests connectivity by sending packets to a remote server and awaiting a response. ipconfig shows config, netstat shows connections, and tracert traces routes.",
      "examTip": "Ping is your first network test—simple and fast."
    },
    {
      "id": 26,
      "question": "A server’s disk IOPS are consistently maxed out. What should you upgrade first?",
      "options": [
        "CPU clock speed",
        "RAM capacity",
        "Storage to faster SSDs",
        "Network to 10GbE"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Upgrading to faster SSDs increases IOPS, directly addressing disk performance. CPU, RAM, and network upgrades help other areas, not IOPS.",
      "examTip": "IOPS bottlenecks need storage speed—SSDs are the fix."
    },
    {
      "id": 27,
      "question": "Which physical control best prevents tailgating into a server room?",
      "options": [
        "Security cameras",
        "Mantrap entry system",
        "RFID card readers",
        "Perimeter fencing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A mantrap allows only one person through at a time, preventing tailgating. Cameras monitor, RFID controls access, and fencing secures perimeters, but none stop tailgating directly.",
      "examTip": "Mantraps enforce single entry—anti-tailgating champs."
    },
    {
      "id": 28,
      "question": "A server’s RAID 6 array loses two drives. What is the operational impact?",
      "options": [
        "Array fails, data is lost",
        "Array remains operational",
        "Performance drops significantly",
        "Rebuild starts automatically"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 6 tolerates two drive failures with dual parity, keeping the array operational. Data isn’t lost, performance may dip slightly, and rebuild requires replacement drives.",
      "examTip": "RAID 6 handles two failures—redundancy at its best."
    },
    {
      "id": 29,
      "question": "Which protocol secures data in transit between a server and a client?",
      "options": [
        "HTTP",
        "HTTPS",
        "FTP",
        "SNMP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "HTTPS (HTTP Secure) encrypts data in transit using SSL/TLS. HTTP, FTP, and SNMP lack inherent encryption for this purpose.",
      "examTip": "HTTPS means secure transit—look for the ‘S’."
    },
    {
      "id": 30,
      "question": "A server’s fans run at maximum speed unexpectedly. What should you check first?",
      "options": [
        "RAID controller status",
        "Temperature sensor readings",
        "BIOS fan control settings",
        "Power supply voltage"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Faulty temperature sensors can trigger fans to max out as a failsafe. RAID, BIOS, and PSU issues are less likely to cause this directly.",
      "examTip": "Fan spikes often mean sensor trouble—check temps first."
    },
    {
      "id": 31,
      "question": "Which licensing model suits a server hosting multiple VMs with varying workloads?",
      "options": [
        "Per-core licensing",
        "Per-user licensing",
        "Per-server licensing",
        "Per-socket licensing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Per-core licensing scales with VM workloads, leveraging multi-core CPUs efficiently. Per-user fits concurrent users, per-server limits flexibility, and per-socket is less granular.",
      "examTip": "Per-core licensing flexes with virtualization—ideal for VMs."
    },
    {
      "id": 32,
      "question": "A server’s OS installation fails due to hardware incompatibility. Where should you verify compatibility?",
      "options": [
        "RAID controller logs",
        "Hardware Compatibility List (HCL)",
        "System event logs",
        "Vendor firmware notes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The HCL lists supported hardware for an OS, ensuring compatibility. Logs and firmware notes help post-install, not pre-check.",
      "examTip": "HCL is your pre-install checklist—avoid compatibility woes."
    },
    {
      "id": 33,
      "question": "Which replication method ensures zero data loss between two sites?",
      "options": [
        "Asynchronous replication",
        "Synchronous replication",
        "Incremental replication",
        "Snapshot replication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Synchronous replication writes data to both sites simultaneously, ensuring zero loss. Asynchronous allows lag, incremental is backup-based, and snapshots are point-in-time.",
      "examTip": "Synchronous means no lag—no loss."
    },
    {
      "id": 34,
      "question": "A server’s virtual switch fails to pass traffic. What should you check first?",
      "options": [
        "Physical NIC link status",
        "VM guest OS settings",
        "Hypervisor firewall rules",
        "RAID array status"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A virtual switch relies on the physical NIC; if the link is down, traffic stops. Guest OS, firewall, and RAID are downstream issues.",
      "examTip": "Virtual networking starts with physical links—check NICs first."
    },
    {
      "id": 35,
      "question": "Which decommissioning step ensures data cannot be recovered from a server’s drives?",
      "options": [
        "Formatting the drives",
        "Multiple-pass disk wiping",
        "Removing drives from RAID",
        "Reinstalling the OS"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multiple-pass disk wiping overwrites data, making recovery nearly impossible. Formatting, RAID removal, and OS reinstalls leave data recoverable.",
      "examTip": "Wipe drives thoroughly—security demands it."
    },
    {
      "id": 36,
      "question": "A server’s application performance drops after a patch. What should you do first?",
      "options": [
        "Roll back the patch",
        "Increase VM resources",
        "Check application logs",
        "Upgrade the hardware"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Application logs reveal why performance dropped post-patch (e.g., errors or incompatibilities). Rolling back, adding resources, or upgrading come after diagnosis.",
      "examTip": "Logs are your first clue post-patch—diagnose before acting."
    },
    {
      "id": 37,
      "question": "Which network cable type supports 10GbE over 100 meters?",
      "options": [
        "Cat5e",
        "Cat6",
        "Cat6a",
        "Cat7"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Cat6a supports 10GbE up to 100 meters reliably. Cat5e tops at 1GbE, Cat6 at 55 meters for 10GbE, and Cat7 is overkill for most uses.",
      "examTip": "Cat6a is the sweet spot for 10GbE—range and speed."
    },
    {
      "id": 38,
      "question": "A server’s RAID controller battery fails. What is the immediate impact?",
      "options": [
        "Array goes offline",
        "Write performance decreases",
        "Data is lost on reboot",
        "Read speeds drop"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A failed RAID battery disables write-back caching, forcing write-through mode and slowing writes. The array stays online, data isn’t lost, and reads are unaffected.",
      "examTip": "Battery failure hits write speed—cache matters."
    },
    {
      "id": 39,
      "question": "Which access control model assigns permissions based on job roles?",
      "options": [
        "DAC",
        "MAC",
        "RBAC",
        "Rule-based"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RBAC (Role-Based Access Control) ties permissions to roles, simplifying management. DAC is discretionary, MAC is mandatory, and rule-based uses conditions.",
      "examTip": "RBAC aligns with jobs—streamlines permissions."
    },
    {
      "id": 40,
      "question": "A server’s SAN performance drops. What should you check first?",
      "options": [
        "RAID parity settings",
        "Fibre Channel HBA status",
        "Server CPU utilization",
        "Network switch logs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The Fibre Channel HBA connects the server to the SAN; if it’s failing, performance drops. RAID, CPU, and switch issues are secondary for SAN-specific problems.",
      "examTip": "SAN issues? Check the HBA—your SAN lifeline."
    },
    {
      "id": 41,
      "question": "Which backup method combines incremental backups into a single file for faster restores?",
      "options": [
        "Differential",
        "Synthetic full",
        "Snapshot",
        "Full"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Synthetic full backups merge incremental backups into one file, speeding up restores. Differential grows over time, snapshots are instant copies, and full is standalone.",
      "examTip": "Synthetic full speeds restores—efficiency in action."
    },
    {
      "id": 42,
      "question": "A server’s disk fails in a RAID 1 array. What should you do first?",
      "options": [
        "Rebuild the array immediately",
        "Replace the failed disk",
        "Back up the remaining data",
        "Update the RAID firmware"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Backing up the remaining data protects against a second failure during replacement. Replacing or rebuilding without backup risks total loss, and firmware isn’t urgent.",
      "examTip": "Backup first in RAID failures—safety over speed."
    },
    {
      "id": 43,
      "question": "Which network troubleshooting tool traces the path packets take to a destination?",
      "options": [
        "ping",
        "netstat",
        "tracert",
        "nslookup"
      ],
      "correctAnswerIndex": 2,
      "explanation": "tracert (traceroute) maps the packet path, identifying latency or failures. Ping tests reachability, netstat shows connections, and nslookup resolves DNS.",
      "examTip": "tracert finds the route—great for pinpointing network issues."
    },
    {
      "id": 44,
      "question": "A server’s VM fails to start after a hypervisor update. What should you check first?",
      "options": [
        "VM guest OS patches",
        "Hypervisor compatibility with VM",
        "Physical NIC status",
        "Storage array health"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A hypervisor update may break VM compatibility (e.g., version mismatch), preventing startup. Guest OS, NIC, and storage are downstream issues.",
      "examTip": "Post-update VM issues? Check hypervisor compatibility first."
    },
    {
      "id": 45,
      "question": "Which physical security feature protects against electromagnetic interference (EMI) in a server room?",
      "options": [
        "Biometric locks",
        "Faraday cage shielding",
        "Mantrap systems",
        "CCTV cameras"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Faraday cage shielding blocks EMI, protecting sensitive equipment. Locks, mantraps, and cameras secure access, not EMI.",
      "examTip": "EMI needs shielding—Faraday is your friend."
    },
    {
      "id": 46,
      "question": "A server’s RAID 10 array loses one drive. What is the operational status?",
      "options": [
        "Array fails completely",
        "Array remains fully operational",
        "Performance drops significantly",
        "Data is inaccessible until rebuilt"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 10 mirrors and stripes; one drive loss per mirror set leaves the array operational, though redundancy is reduced. Performance may dip slightly, but data stays accessible.",
      "examTip": "RAID 10 survives single failures—mirrors save the day."
    },
    {
      "id": 47,
      "question": "Which protocol ensures secure management of network devices with encryption?",
      "options": [
        "SNMPv1",
        "SNMPv3",
        "Telnet",
        "FTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SNMPv3 provides encrypted management of network devices. SNMPv1 lacks security, Telnet is insecure, and FTP transfers files.",
      "examTip": "SNMPv3 secures device management—v3 is the key."
    },
    {
      "id": 48,
      "question": "A server’s performance degrades during backups. What should you adjust?",
      "options": [
        "Increase CPU cores",
        "Schedule backups off-peak",
        "Upgrade to faster RAM",
        "Add a second NIC"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Scheduling backups during off-peak hours reduces contention with live workloads. Hardware upgrades help but don’t address timing conflicts directly.",
      "examTip": "Timing backups avoids peak load—plan wisely."
    },
    {
      "id": 49,
      "question": "Which documentation type tracks server hardware lifecycle and warranty details?",
      "options": [
        "Network diagrams",
        "Asset inventory",
        "Performance baselines",
        "Disaster recovery plans"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asset inventory logs hardware details like serial numbers, warranties, and lifecycle status. Diagrams map networks, baselines track performance, and DR plans outline recovery.",
      "examTip": "Asset inventory is your hardware ledger—track everything."
    },
    {
      "id": 50,
      "question": "A server’s NTP sync fails, causing log timestamp issues. What should you check first?",
      "options": [
        "Firewall port 123 status",
        "DNS resolution for NTP server",
        "Server BIOS clock settings",
        "Network switch latency"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NTP uses UDP port 123; a blocked firewall port prevents sync. DNS, BIOS, and latency are secondary if the port is closed.",
      "examTip": "NTP needs port 123 open—firewall is the first stop."
    },
    {
      "id": 51,
      "question": "A server migration project requires transferring 4TB of data between data centers with minimal downtime. Which approach is most efficient?",
      "options": [
        "Network-based replication over a dedicated link",
        "Disk-to-disk backup with courier transport",
        "Virtual machine conversion and migration",
        "Storage array snapshot with delta transfers"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Storage array snapshots with delta transfers minimize downtime by capturing the initial data state and then only transferring changes. Network replication works but may take longer, physical transport introduces delays, and VM conversion adds complexity.",
      "examTip": "Delta transfers optimize migration time—focus on changing data only."
    },
    {
      "id": 52,
      "question": "A server's RAM utilization consistently exceeds 90% during peak hours. What is the most appropriate solution?",
      "options": [
        "Enable memory compression in the OS",
        "Increase the page file/swap space size",
        "Add additional physical memory modules",
        "Implement application-level caching"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Adding physical memory directly addresses the resource constraint. Memory compression and increased page file size are software workarounds that don't solve the underlying hardware limitation, and application caching may not reduce RAM usage.",
      "examTip": "Hardware solutions for hardware problems—software workarounds don't fix resource constraints."
    },
    {
      "id": 53,
      "question": "Which server deployment model provides the most consistent performance for a predictable, steady workload?",
      "options": [
        "Public cloud with reserved instances",
        "Private cloud with dedicated hardware",
        "Bare-metal server with direct hardware access",
        "Hybrid cloud with burst capability"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Bare-metal servers provide direct hardware access without virtualization overhead, ensuring consistent performance for steady workloads. Cloud options introduce potential variability, and hybrid adds complexity not needed for predictable loads.",
      "examTip": "Predictable workloads benefit from dedicated resources—virtualization adds overhead."
    },
    {
      "id": 54,
      "question": "A server monitoring alert shows sporadic packet loss between two servers. Which troubleshooting tool best identifies if the issue is occurring at a specific network hop?",
      "options": [
        "ping with varied packet sizes",
        "netstat connection statistics",
        "traceroute with timing information",
        "tcpdump packet capture"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Traceroute with timing information identifies packet loss at specific hops in the network path. Ping shows end-to-end loss, netstat shows connection states, and tcpdump captures packets but doesn't trace the path.",
      "examTip": "Traceroute pinpoints network problems by hop—essential for path troubleshooting."
    },
    {
      "id": 55,
      "question": "When implementing a Windows Server storage solution that requires thin provisioning, deduplication, and tiering, which technology is most appropriate?",
      "options": [
        "Storage Spaces Direct",
        "ReFS with integrity streams",
        "iSCSI Target Server",
        "NTFS with compression"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Storage Spaces Direct supports thin provisioning, deduplication, and storage tiering in a software-defined solution. ReFS lacks native deduplication, iSCSI Target doesn't handle tiering, and NTFS compression isn't equivalent to deduplication or tiering.",
      "examTip": "Storage Spaces Direct offers advanced features for software-defined storage in Windows."
    },
    {
      "id": 56,
      "question": "A RAID 5 array with four 2TB drives has a usable capacity closest to:",
      "options": [
        "6TB",
        "8TB",
        "4TB",
        "2TB"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A RAID 5 array uses one drive for parity, so with four 2TB drives, the usable capacity is (n-1) × drive size = 3 × 2TB = 6TB. RAID 5 sacrifices one drive's worth of space for redundancy.",
      "examTip": "For RAID 5 capacity, remember the n-1 formula—one drive for parity."
    },
    {
      "id": 57,
      "question": "Which service account configuration poses the least security risk for a SQL Server installation?",
      "options": [
        "Local System account with admin privileges",
        "Domain Administrator account",
        "Managed Service Account with least privilege",
        "Local user account with admin privileges"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Managed Service Accounts with least privilege provide automatic password management while limiting permissions to only what's required. Local System has excessive privileges, Domain Admin is severely over-privileged, and local admin accounts lack centralized management.",
      "examTip": "Least privilege principle for service accounts—automated management is a bonus."
    },
    {
      "id": 58,
      "question": "A server's OS becomes unresponsive but still responds to ping. Which remote management feature would allow an administrator to troubleshoot without physical access?",
      "options": [
        "SNMP monitoring",
        "Out-of-band management",
        "Wake-on-LAN",
        "Remote desktop protocol"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Out-of-band management (like iLO, iDRAC, IPMI) operates independently of the OS, allowing troubleshooting when the OS is unresponsive. SNMP only monitors, Wake-on-LAN only powers on, and RDP requires the OS to function.",
      "examTip": "Out-of-band management works when the OS fails—essential for remote sites."
    },
    {
      "id": 59,
      "question": "Which technology allows a server to boot from a LUN on a SAN instead of local disks?",
      "options": [
        "iSCSI boot",
        "Network boot (PXE)",
        "UEFI secure boot",
        "Wake-on-LAN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "iSCSI boot enables servers to boot from SAN LUNs over the network. PXE boots from a network server but not directly from SAN storage, UEFI secure boot verifies boot files, and Wake-on-LAN remotely powers on systems.",
      "examTip": "iSCSI boot enables diskless servers—simplifying hardware and enabling stateless computing."
    },
    {
      "id": 60,
      "question": "A server requires consistent 10GbE connectivity with the lowest CPU overhead. Which networking technology achieves this?",
      "options": [
        "Software-defined networking (SDN)",
        "NIC teaming with load balancing",
        "RDMA over Converged Ethernet (RoCE)",
        "Virtual LAN (VLAN) tagging"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RDMA over Converged Ethernet (RoCE) bypasses the CPU for network processing, reducing overhead while maintaining full 10GbE throughput. SDN adds abstraction overhead, NIC teaming doesn't reduce CPU load, and VLAN tagging addresses traffic segmentation, not CPU efficiency.",
      "examTip": "For CPU-efficient networking, RDMA technologies bypass the kernel—critical for high-throughput servers."
    },
    {
      "id": 61,
      "question": "Which Linux file system change requires the least downtime to implement on a production server?",
      "options": [
        "Converting from ext3 to ext4",
        "Implementing LVM thin provisioning",
        "Migrating from ext4 to XFS",
        "Enabling disk quotas"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Implementing LVM thin provisioning can be done on existing logical volumes without reformatting, requiring minimal downtime. File system conversions (ext3 to ext4 or ext4 to XFS) require reformatting, and quota implementation may require remounting.",
      "examTip": "LVM changes often need less downtime—logical management is more flexible."
    },
    {
      "id": 62,
      "question": "A server is experiencing high CPU wait time. Which component is most likely causing the bottleneck?",
      "options": [
        "Insufficient RAM",
        "Slow storage subsystem",
        "Network congestion",
        "Poor application threading"
      ],
      "correctAnswerIndex": 1,
      "explanation": "High CPU wait time indicates the CPU is idle waiting for I/O operations, typically pointing to a slow storage subsystem. RAM issues cause swapping, network issues show different metrics, and application threading affects CPU utilization patterns differently.",
      "examTip": "High wait time means I/O bottlenecks—check storage first."
    },
    {
      "id": 63,
      "question": "Which hardware component verification is most critical before applying a firmware update to a server?",
      "options": [
        "Memory compatibility with new firmware",
        "CPU stepping level support",
        "Backup power system functionality",
        "Current firmware version and update path"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Verifying the current firmware version and proper update path prevents failed updates or bricking the device. Some firmware requires sequential updates; skipping versions can cause failures. Component compatibility is checked by the update itself, and backup power is a general precaution.",
      "examTip": "Firmware update paths matter—check version dependencies before upgrading."
    },
    {
      "id": 64,
      "question": "When implementing a hyperconverged infrastructure, which factor most significantly influences node count calculation?",
      "options": [
        "Expected storage IOPS requirements",
        "Total RAM needed across all VMs",
        "Failure domain resilience requirements",
        "Network throughput between nodes"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Failure domain resilience requirements determine how many node failures the system can tolerate while maintaining availability, directly affecting minimum node count. IOPS, RAM, and network are resource sizing factors but don't determine the minimum node count like resilience requirements do.",
      "examTip": "Resilience drives node count—N+1 or N+2 planning is fundamental for hyperconverged."
    },
    {
      "id": 65,
      "question": "Which authentication mechanism provides the most security for remote server SSH access?",
      "options": [
        "Password authentication with complexity requirements",
        "Kerberos ticket-based authentication",
        "Public key authentication with passphrase protection",
        "Certificate-based authentication with hardware tokens"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Certificate-based authentication with hardware tokens combines something you have (hardware token) with something you know (PIN), with certificates that can't be brute-forced, providing multi-factor security. The other options offer less comprehensive protection or rely on fewer factors.",
      "examTip": "Hardware tokens add physical security—multi-factor is stronger than any single factor."
    },
    {
      "id": 66,
      "question": "A server runs critical applications that cannot tolerate any downtime. Which clustering approach is most appropriate?",
      "options": [
        "Active-passive failover cluster",
        "Active-active load balanced cluster",
        "N+1 redundancy cluster",
        "Stretched cluster across multiple sites"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Active-active load balanced clustering maintains full service during maintenance or failures with no transition period. Active-passive requires failover time, N+1 ensures spare capacity but may need failover, and stretched clusters add complexity across sites.",
      "examTip": "Active-active means no failover delay—critical for true zero-downtime applications."
    },
    {
      "id": 67,
      "question": "Which protocol provides the most efficient data transfer for backups across a WAN with high latency?",
      "options": [
        "HTTPS with chunked transfer encoding",
        "FTP with multiple parallel connections",
        "SMB with opportunistic locks",
        "RDMA with TCP offload"
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTPS with chunked transfer encoding handles high latency well through persistent connections, compression, and optimized transfer sizes. FTP lacks built-in compression, SMB performs poorly with high latency, and RDMA typically requires specialized hardware and low latency.",
      "examTip": "For high-latency transfers, protocol efficiency and compression matter more than raw speed."
    },
    {
      "id": 68,
      "question": "A server deployment requires maximum storage performance for a database workload. Which configuration is most effective?",
      "options": [
        "NVMe SSDs in RAID 10 with dedicated controller",
        "SAS SSDs in RAID 5 with battery-backed cache",
        "SATA SSDs in RAID 0 with OS caching",
        "Fibre Channel SAN with tiered storage"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NVMe SSDs in RAID 10 provide the highest performance through direct PCIe connectivity (avoiding SAS/SATA bottlenecks) and RAID 10's balanced read/write performance. SAS SSDs are slower than NVMe, RAID 5 has write penalties, RAID 0 lacks redundancy, and SANs add network latency.",
      "examTip": "NVMe with RAID 10 optimizes both interface speed and I/O patterns—ideal for databases."
    },
    {
      "id": 69,
      "question": "When implementing a scalable server monitoring solution, which approach best handles monitoring across multiple platforms?",
      "options": [
        "Agent-based monitoring with platform-specific collectors",
        "SNMP polling with custom MIBs for each platform",
        "Agentless monitoring using platform APIs",
        "Log aggregation with centralized analysis"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Log aggregation with centralized analysis works across all platforms since logging is universal, requiring minimal platform-specific configuration. Agent-based and SNMP solutions need platform-specific components, and API-based monitoring requires different integration for each platform.",
      "examTip": "Logs exist everywhere—aggregation scales across heterogeneous environments."
    },
    {
      "id": 70,
      "question": "A Windows server experiences increased memory usage over time without corresponding activity increases. Which diagnostic tool best identifies the specific process causing the memory leak?",
      "options": [
        "Task Manager Memory tab",
        "Performance Monitor with memory counters",
        "User Mode Dump Analysis with Debug Diagnostic Tool",
        "Windows Event Viewer System logs"
      ],
      "correctAnswerIndex": 2,
      "explanation": "User Mode Dump Analysis with Debug Diagnostic Tool can capture and analyze memory dumps to identify specific memory leaks within processes. Task Manager and Performance Monitor show symptoms but not root causes, and Event Viewer rarely captures memory leak details.",
      "examTip": "Memory leaks require dump analysis—surface tools show symptoms, not causes."
    },
    {
      "id": 71,
      "question": "Which server security configuration most effectively prevents buffer overflow attacks?",
      "options": [
        "Implementing ASLR (Address Space Layout Randomization)",
        "Configuring Data Execution Prevention (DEP)",
        "Enabling Control Flow Guard (CFG)",
        "Regular application patching"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Control Flow Guard (CFG) specifically prevents buffer overflow attacks by verifying the integrity of indirect function calls at runtime, preventing attackers from easily jumping to shellcode. ASLR randomizes memory locations, DEP prevents data execution, and patching removes known vulnerabilities, but CFG directly addresses the control flow hijacking that makes buffer overflows dangerous.",
      "examTip": "CFG specifically targets exploitation techniques—critical for legacy applications."
    },
    {
      "id": 72,
      "question": "Which RAID configuration option provides the optimal balance of capacity, performance, and redundancy for a file server with mixed read/write workloads?",
      "options": [
        "RAID 6 with distributed parity",
        "RAID 5 with hot spare",
        "RAID 10 with SSD caching",
        "RAID 50 (5+0) spanning"
      ],
      "correctAnswerIndex": 3,
      "explanation": "RAID 50 combines RAID 5 arrays in a RAID 0 configuration, balancing redundancy with performance for mixed workloads while maximizing capacity. RAID 6 has higher write penalties, RAID 5 with hot spare offers less performance, and RAID 10 has lower capacity efficiency despite good performance.",
      "examTip": "Nested RAID combines benefits—RAID 50 balances multiple factors effectively."
    },
    {
      "id": 73,
      "question": "Which service should be configured for centralized certificate management across multiple Windows servers?",
      "options": [
        "Key Distribution Service (KDS)",
        "Active Directory Certificate Services (AD CS)",
        "Certificate Revocation List Distribution Point",
        "Credential Manager"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Active Directory Certificate Services (AD CS) provides centralized certificate issuance, renewal, and management for Windows environments. KDS handles service account keys, CRL Distribution Points only handle revocation lists, and Credential Manager is for local credential storage.",
      "examTip": "AD CS centralizes PKI management—essential for enterprise certificate deployment."
    },
    {
      "id": 74,
      "question": "A server with 10GbE networking experiences packet drops during high traffic periods. Which feature should be adjusted to resolve this issue?",
      "options": [
        "Receive Side Scaling (RSS)",
        "TCP Window Scaling",
        "Jumbo frames MTU size",
        "VLAN Quality of Service (QoS)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Receive Side Scaling (RSS) distributes network processing across multiple CPU cores, preventing single-core bottlenecks during high traffic. TCP Window Scaling affects throughput but not packet drops, Jumbo frames reduce overhead but don't address processing limitations, and QoS prioritizes traffic without increasing processing capacity.",
      "examTip": "RSS parallelizes network processing—critical for 10GbE and faster networks."
    },
    {
      "id": 75,
      "question": "Which backup validation technique provides the highest confidence level for disaster recovery?",
      "options": [
        "Backup media verification scan",
        "Database consistency check after restore",
        "Full application functionality testing in isolated environment",
        "Automated backup log analysis"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Full application functionality testing in an isolated environment confirms the entire stack works after restoration, not just that files are recoverable. Media verification checks backup integrity, consistency checks verify database structure, and log analysis confirms process completion, but none test actual functionality.",
      "examTip": "Test full functionality post-restore—recoverable doesn't always mean usable."
    },
    {
      "id": 76,
      "question": "A virtualization host uses local SSDs for VM storage. Which feature best improves VM migration speed between hosts?",
      "options": [
        "CPU reservation for migration tasks",
        "Dedicated vMotion network",
        "Storage deduplication",
        "Changed block tracking"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Changed block tracking identifies and transfers only modified data blocks during migration, significantly reducing transfer volume and time. CPU reservation helps processing, dedicated networks improve bandwidth, and deduplication reduces storage size but not necessarily transfer time.",
      "examTip": "Track changed blocks to minimize migration data—speed depends on delta size, not total size."
    },
    {
      "id": 77,
      "question": "When implementing server infrastructure as code, which practice most effectively prevents configuration drift?",
      "options": [
        "Weekly compliance scanning",
        "Immutable infrastructure deployment",
        "Scheduled configuration reapplication",
        "Detailed change management documentation"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Immutable infrastructure deployment replaces servers rather than modifying them, eliminating drift by design. Compliance scanning detects drift after it occurs, scheduled reapplication corrects drift periodically but allows temporary drift, and documentation doesn't prevent drift.",
      "examTip": "Immutable means no modifications—each change is a complete deployment."
    },
    {
      "id": 78,
      "question": "A server hosting critical services requires maximum reliability. Which memory configuration is most effective?",
      "options": [
        "ECC memory with memory mirroring",
        "Non-ECC memory with higher frequency",
        "ECC memory with memory sparing",
        "Registered memory with locked timing"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ECC memory with mirroring combines error correction with complete redundancy, providing the highest reliability. Non-ECC lacks error protection regardless of speed, memory sparing has recovery delay after failure, and registered memory with locked timing improves stability but lacks redundancy.",
      "examTip": "Memory mirroring with ECC offers redundancy plus correction—maximum protection."
    },
    {
      "id": 79,
      "question": "Which tool best analyzes server disk subsystem latency at the application level?",
      "options": [
        "iostat with extended statistics",
        "smartctl disk health data",
        "Application Performance Monitoring (APM) tool",
        "fio synthetic load testing"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Application Performance Monitoring (APM) tools track actual application-experienced latency through code profiling, correlating disk operations with application performance. iostat shows system-level latency, smartctl reports health but not performance, and fio tests theoretical not actual application performance.",
      "examTip": "APM measures what matters—application experience trumps raw metrics."
    },
    {
      "id": 80,
      "question": "Which security measure most effectively protects a server from zero-day vulnerabilities?",
      "options": [
        "Next-generation antivirus software",
        "Application allowlisting",
        "Regular security patches",
        "Intrusion Detection System (IDS)"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Application allowlisting prevents unauthorized code execution regardless of vulnerability status, blocking exploits even for unknown vulnerabilities. Antivirus requires signatures, patches address known issues only, and IDS detects but doesn't prevent unknown exploits.",
      "examTip": "Allowlisting blocks unauthorized execution—effective against unknown threats."
    },
    {
      "id": 81,
      "question": "A Linux server experiences storage issues. Which tool provides the most comprehensive analysis of the volume manager configuration?",
      "options": [
        "fdisk -l",
        "pvdisplay and vgdisplay",
        "lsblk --fs",
        "df -h"
      ],
      "correctAnswerIndex": 1,
      "explanation": "pvdisplay and vgdisplay show detailed LVM (Logical Volume Manager) configuration including physical volumes, volume groups, and their relationships. fdisk shows partition tables, lsblk shows block devices and mount points, and df shows filesystem usage but not LVM details.",
      "examTip": "LVM troubleshooting requires specialized tools—pvdisplay and vgdisplay reveal the complete stack."
    },
    {
      "id": 82,
      "question": "Which access control method is most appropriate for a multi-tenant server environment?",
      "options": [
        "Role-based access control with tenant isolation",
        "Discretionary access control with owner permissions",
        "Mandatory access control with security labeling",
        "Rule-based access control with time restrictions"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Mandatory access control with security labeling enforces strict separation between tenants through system-enforced policies, preventing inadvertent data leakage. Role-based control may have permission overlaps, discretionary allows owners to grant excessive permissions, and rule-based doesn't enforce isolation.",
      "examTip": "Multi-tenant security requires strong isolation—mandatory controls enforce separation."
    },
    {
      "id": 83,
      "question": "Which configuration ensures the most effective server cooling in a high-density rack?",
      "options": [
        "Front-to-back airflow with hot aisle containment",
        "Overhead cooling with downward air delivery",
        "Side-to-side airflow with alternating server orientation",
        "Perimeter cooling with open rack design"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Front-to-back airflow with hot aisle containment creates a consistent cooling path, preventing hot and cold air mixing and increasing cooling efficiency. Overhead cooling creates mixing, side-to-side is inefficient in racks, and perimeter cooling with open racks allows significant air mixing.",
      "examTip": "Hot/cold aisle containment maximizes efficiency—proper airflow management is key."
    },
    {
      "id": 84,
      "question": "A server in a VLAN-segmented network needs to communicate with devices across multiple VLANs. Which network configuration is most appropriate?",
      "options": [
        "Multiple physical NICs each connected to different VLANs",
        "Single NIC with 802.1Q VLAN tagging",
        "Private VLAN with promiscuous port",
        "Routed ports with inter-VLAN routing"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Single NIC with 802.1Q VLAN tagging allows the server to communicate on multiple VLANs through one physical connection, simplifying cabling and configuration. Multiple NICs waste ports, private VLANs limit communication, and routed ports add complexity.",
      "examTip": "802.1Q tagging enables multi-VLAN access through one cable—efficient and flexible."
    },
    {
      "id": 85,
      "question": "Which storage protocol provides the lowest latency for high-performance database servers?",
      "options": [
        "iSCSI over 10GbE",
        "NVMe over Fabrics (NVMe-oF)",
        "Fibre Channel at 32Gbps",
        "Network File System (NFS) v4.2"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NVMe over Fabrics extends the low-latency benefits of NVMe to networked storage, maintaining sub-millisecond latency. iSCSI adds TCP/IP overhead, Fibre Channel has protocol overhead despite high bandwidth, and NFS adds file system layer latency.",
      "examTip": "NVMe-oF maintains local NVMe advantages—lowest latency for networked storage."
    },
    {
      "id": 86,
      "question": "A server runs a memory-intensive application with large datasets. Which memory configuration provides optimal performance?",
      "options": [
        "Single-rank DIMMs in all slots",
        "Dual-rank DIMMs in fewer slots",
        "Highest frequency compatible DIMMs",
        "Maximum memory channels utilized"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Utilizing all memory channels provides maximum memory bandwidth by enabling parallel memory access, critical for large datasets. DIMM rank affects density vs. speed tradeoffs but is secondary to channel utilization, and frequency benefits can be outweighed by insufficient channels.",
      "examTip": "Memory channels multiply bandwidth—maxing out channels is priority one."
    },
    {
      "id": 87,
      "question": "When implementing server automation, which authentication method provides the best balance of security and ease of maintenance for API-driven configuration?",
      "options": [
        "Username/password with regular rotation",
        "X.509 certificate authentication",
        "OAuth token-based authentication",
        "API keys with IP restrictions"
      ],
      "correctAnswerIndex": 2,
      "explanation": "OAuth token-based authentication provides secure, temporary access with centralized control and revocation capabilities, ideal for automation systems. Username/password requires risky storage, certificates have complex lifecycle management, and API keys become difficult to track and rotate at scale.",
      "examTip": "Token-based auth streamlines secure automation—short-lived credentials reduce risk."
    },
    {
      "id": 88,
      "question": "A high-availability database cluster experiences split-brain scenarios. Which component should be implemented to prevent this?",
      "options": [
        "Virtual IP failover mechanism",
        "Shared storage heartbeat",
        "Quorum witness server",
        "Database transaction log shipping"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A quorum witness server provides an independent vote to maintain odd-numbered voting members, preventing split-brain by ensuring a clear majority during network partitions. Virtual IPs don't prevent split decisions, shared storage becomes a single point of failure, and log shipping is for replication, not quorum.",
      "examTip": "Quorum requires an odd number of voters—witness servers break the tie."
    },
    {
      "id": 89,
      "question": "A server reaches 90% CPU utilization during peak hours. Which performance metric best determines if this is actually causing a problem?",
      "options": [
        "Load average values",
        "Context switches per second",
        "Application response time",
        "CPU run queue length"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Application response time directly measures the impact on users, determining whether the CPU utilization is problematic. Load average includes waiting processes, context switches indicate overhead but not impact, and run queue is a symptom rather than an impact measure.",
      "examTip": "User experience metrics reveal real problems—resource utilization alone doesn't tell the full story."
    },
    {
      "id": 90,
      "question": "Which server management practice most effectively reduces troubleshooting time during incidents?",
      "options": [
        "Configuration management database (CMDB)",
        "Detailed runbooks with common scenarios",
        "Automated monitoring with alerting",
        "Regular staff training on systems"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Detailed runbooks with common scenarios provide immediate, tested guidance during incidents, reducing troubleshooting time. CMDB helps understand relationships, monitoring detects issues, and training improves skills, but runbooks directly accelerate incident resolution.",
      "examTip": "Runbooks codify expert knowledge—significantly reducing incident resolution time."
    },
    {
      "id": 91,
      "question": "Which system event should trigger an automatic failover in a high-availability server cluster?",
      "options": [
        "CPU utilization exceeding 95% for 2 minutes",
        "System disk reaching 90% capacity",
        "Application response time over threshold",
        "Kernel panic or system crash"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Kernel panic or system crash indicates complete node failure requiring immediate failover. High CPU, disk capacity, and response time issues should trigger alerts and potential manual intervention but typically don't warrant automatic failover as they're not definitive failures.",
      "examTip": "Auto-failover for definitive failures only—performance issues need investigation first."
    },
    {
      "id": 92,
      "question": "Which storage configuration best protects against silent data corruption on a file server?",
      "options": [
        "Hardware RAID with battery-backed cache",
        "File system with checksumming and scrubbing",
        "Enterprise SSDs with power loss protection",
        "Regular backup and restore verification"
      ],
      "correctAnswerIndex": 1,
      "explanation": "File systems with checksumming and scrubbing (like ZFS or Btrfs) detect and repair silent data corruption by validating data against checksums. RAID doesn't detect corruption, enterprise SSDs prevent write corruption only, and backups might preserve corrupted data.",
      "examTip": "Silent corruption requires data validation—checksumming file systems actively detect and repair."
    },
    {
      "id": 93,
      "question": "A Windows Server cluster needs to ensure application data consistency during failover. Which feature is most important to configure?",
      "options": [
        "Persistent reservation on shared storage",
        "Application-aware quorum settings",
        "Synchronous storage replication",
        "Witness file share majority"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Synchronous storage replication ensures data consistency by confirming writes are completed on all nodes before acknowledging completion, preventing data loss during failover. Persistent reservations control access but don't ensure consistency, quorum settings affect failover decisions but not data consistency, and witness shares affect quorum but not data.",
      "examTip": "Synchronous replication guarantees consistency—no acknowledged writes are lost."
    },
    {
      "id": 94,
      "question": "When migrating a physical server to a virtual environment, which step most accurately determines required VM resources?",
      "options": [
        "Copying existing hardware specifications",
        "Analyzing historical performance data",
        "Running a P2V assessment tool",
        "Calculating application minimum requirements"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Analyzing historical performance data reveals actual resource utilization patterns rather than provisioned resources, enabling right-sizing the VM. Copying hardware specs often leads to over-provisioning, P2V tools give points-in-time snapshots, and minimum requirements often don't reflect real-world usage.",
      "examTip": "Historical data shows actual usage—right-size VMs based on real patterns."
    },
    {
      "id": 95,
      "question": "Which hardening technique most effectively reduces the attack surface of a Linux web server?",
      "options": [
        "Disabling root SSH access",
        "Implementing SELinux in enforcing mode",
        "Enabling automatic updates",
        "Installing a host-based firewall"
      ],
      "correctAnswerIndex": 1,
      "explanation": "SELinux in enforcing mode implements mandatory access controls that constrain processes even if they're compromised, preventing privilege escalation and lateral movement. Disabling root SSH addresses one vector, automatic updates fix known vulnerabilities but not zero-days, and firewalls control network access only.",
      "examTip": "SELinux constrains processes even when compromised—defense in depth at the OS level."
    },
    {
      "id": 96,
      "question": "Which factor most significantly affects the choice between UEFI and legacy BIOS for server deployment?",
      "options": [
        "Support for drives larger than 2TB",
        "Secure Boot requirements",
        "Network boot capabilities",
        "OS compatibility"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Secure Boot requirements necessitate UEFI as legacy BIOS cannot implement Secure Boot, which validates boot loaders cryptographically to prevent rootkits. Drive size limits can be addressed with GPT partitioning, both support network booting, and modern OS versions support both boot methods.",
      "examTip": "Secure Boot demands UEFI—it's the key security advantage over legacy BIOS."
    },
    {
      "id": 97,
      "question": "A cloud-based server instance must automatically scale based on workload. Which metric most accurately triggers appropriate scaling actions?",
      "options": [
        "CPU utilization percentage",
        "Memory consumption rate",
        "Application request queue length",
        "Network I/O throughput"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Application request queue length directly measures the work pending processing, providing the most accurate indicator of capacity needs. CPU and memory metrics may spike briefly or remain low during real bottlenecks, and network I/O reflects completed not pending work.",
      "examTip": "Queue length measures actual demand—scale based on pending work, not resource utilization."
    },
    {
      "id": 98,
      "question": "Which practice most effectively ensures consistent server configurations across development, testing, and production environments?",
      "options": [
        "Manual configuration with detailed documentation",
        "Configuration management tools with environment-specific variables",
        "Golden image deployment with post-configuration scripts",
        "Container-based application deployment"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Configuration management tools with environment-specific variables automate consistent configurations while accommodating necessary differences between environments through parameterization. Manual configuration is error-prone, golden images lack flexibility for environment differences, and containers primarily address application not server configurations.",
      "examTip": "Code-driven configuration with environment variables maintains consistency while supporting needed variations."
    },
    {
      "id": 99,
      "question": "A server hosts an application with unpredictable, bursty I/O patterns. Which storage configuration provides the most consistent performance?",
      "options": [
        "SSD caching with tiered storage",
        "All-flash array with QoS limits",
        "NVMe drives with overprovisioning",
        "RAID 10 with large controller cache"
      ],
      "correctAnswerIndex": 2,
      "explanation": "NVMe drives with overprovisioning maintain consistent performance during bursty I/O by reserving flash capacity for wear leveling and garbage collection, preventing performance degradation during heavy write bursts. Tiered storage has migration delays, QoS limits performance, and controller cache helps but can be overwhelmed by extended bursts.",
      "examTip": "Overprovisioned NVMe maintains performance during I/O bursts—reserve capacity for consistency."
    },
    {
      "id": 100,
      "question": "Which IPMI configuration poses the greatest security risk to a server?",
      "options": [
        "Default credentials on the management interface",
        "IPMI over LAN enabled on the public network",
        "Serial over LAN (SOL) console redirection",
        "SNMP read-only access for monitoring"
      ],
      "correctAnswerIndex": 1,
      "explanation": "IPMI over LAN enabled on the public network exposes the management interface (with known vulnerabilities) to untrusted networks. Default credentials can be changed, SOL console redirection requires authentication, and read-only SNMP has limited capabilities for attacks.",
      "examTip": "Never expose IPMI to public networks—out-of-band management requires strict network isolation."
    }
  ]
});
