db.tests.insertOne({
  "category": "serverplus",
  "testId": 5,
  "testName": "Server+ Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A server in a high-density rack experiences intermittent shutdowns during peak load times. The server’s dual PSUs are connected to a single PDU rated for its maximum draw. What is the most likely cause?\n\nA. The PDU is overloaded from shared load with other servers.\nB. The server’s PSUs are failing to load-balance effectively.\nC. The server’s cooling system cannot handle peak thermal output.\nD. The server’s BIOS power management settings are misconfigured.",
      "options": [
        "The PDU is overloaded from shared load with other servers.",
        "The server’s PSUs are failing to load-balance effectively.",
        "The server’s cooling system cannot handle peak thermal output.",
        "The server’s BIOS power management settings are misconfigured."
      ],
      "correctAnswerIndex": 0,
      "explanation": "In a high-density rack, a PDU rated for one server’s maximum draw can still be overloaded if it powers multiple servers, especially during peak load. PSU load-balancing issues, cooling limitations, and BIOS misconfigurations are plausible but less likely without specific symptoms like uneven PSU wear, overheating alerts, or power profile mismatches.",
      "examTip": "In dense setups, always evaluate PDU capacity against total rack load, not just one server."
    },
    {
      "id": 2,
      "question": "A database server’s performance degrades after switching from RAID 5 to RAID 6 with the same number of drives and a hardware controller. What is the primary reason?\n\nA. RAID 6’s dual parity increases write overhead.\nB. RAID 6 reduces usable capacity, straining I/O.\nC. RAID 6 lacks the same hardware acceleration as RAID 5.\nD. RAID 6’s parity calculations slow rebuild operations.",
      "options": [
        "RAID 6’s dual parity increases write overhead.",
        "RAID 6 reduces usable capacity, straining I/O.",
        "RAID 6 lacks the same hardware acceleration as RAID 5.",
        "RAID 6’s parity calculations slow rebuild operations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "RAID 6’s dual parity doubles the write penalty over RAID 5’s single parity, directly impacting performance during writes. Capacity reduction affects space, not speed; hardware acceleration is typically consistent across RAID levels; and rebuild times are a secondary concern.",
      "examTip": "More parity means more write work—know the RAID tradeoff."
    },
    {
      "id": 3,
      "question": "A server’s SSDs in a RAID 10 array show early wear despite low write activity. What is the most probable cause?\n\nA. The SSDs are optimized for read-intensive workloads.\nB. The RAID controller’s write-back cache is misconfigured.\nC. The workload involves frequent small-block reads.\nD. The SSDs are low-endurance models.",
      "options": [
        "The SSDs are optimized for read-intensive workloads.",
        "The RAID controller’s write-back cache is misconfigured.",
        "The workload involves frequent small-block reads.",
        "The SSDs are low-endurance models."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Low-endurance SSDs wear out faster even with minimal writes due to limited program/erase cycles. Read-intensive SSDs handle reads well but still wear from writes; misconfigured cache affects performance, not wear; and small reads don’t significantly impact endurance.",
      "examTip": "SSD wear depends on endurance—match it to the workload."
    },
    {
      "id": 4,
      "question": "A server’s network drops after a switch firmware update. It uses NIC teaming with LACP. What should you check first?\n\nA. The switch’s LACP settings post-update.\nB. The server’s NIC driver compatibility.\nC. The server’s IP addressing configuration.\nD. The switch’s VLAN tagging consistency.",
      "options": [
        "The switch’s LACP settings post-update.",
        "The server’s NIC driver compatibility.",
        "The server’s IP addressing configuration.",
        "The switch’s VLAN tagging consistency."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A firmware update could reset or alter LACP settings, disrupting teaming. NIC drivers, IP config, and VLANs are less likely to change with a switch update unless explicitly indicated.",
      "examTip": "Firmware updates can reset configs—verify LACP after changes."
    },
    {
      "id": 5,
      "question": "A server’s SAN data is unencrypted, breaching compliance. What secures data at rest with minimal performance impact?\n\nA. Enable SAN-level encryption.\nB. Apply OS-level file encryption.\nC. Use IPsec for SAN network traffic.\nD. Install a host-based encryption agent.",
      "options": [
        "Enable SAN-level encryption.",
        "Apply OS-level file encryption.",
        "Use IPsec for SAN network traffic.",
        "Install a host-based encryption agent."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SAN-level encryption secures data at rest with hardware acceleration, minimizing performance hits. OS-level and host-based encryption add CPU overhead, while IPsec secures transit, not rest.",
      "examTip": "For data at rest, SAN encryption is fast and efficient."
    },
    {
      "id": 6,
      "question": "A hypervisor with 32 cores runs 10 VMs, each with 4 vCPUs. CPU-ready time spikes at peak usage. What should you adjust first?\n\nA. Add more physical cores to the host.\nB. Decrease vCPUs per VM.\nC. Set CPU affinity for high-priority VMs.\nD. Increase the host’s RAM capacity.",
      "options": [
        "Add more physical cores to the host.",
        "Decrease vCPUs per VM.",
        "Set CPU affinity for high-priority VMs.",
        "Increase the host’s RAM capacity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "High CPU-ready time signals overcommitment (40 vCPUs on 32 cores); reducing vCPUs per VM eases contention. More cores help but cost more; affinity limits flexibility; RAM doesn’t fix CPU waits.",
      "examTip": "CPU-ready spikes? Cut vCPUs—overcommitment kills."
    },
    {
      "id": 7,
      "question": "A server requires a 15-minute RPO. Which backup method meets this with minimal storage use?\n\nA. Continuous data replication.\nB. Hourly incremental backups.\nC. 15-minute differential backups.\nD. Real-time disk snapshots.",
      "options": [
        "Continuous data replication.",
        "Hourly incremental backups.",
        "15-minute differential backups.",
        "Real-time disk snapshots."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Continuous replication syncs data in near-real-time, meeting a 15-minute RPO with efficient storage. Hourly backups miss the mark; differentials grow large; snapshots consume more space over time.",
      "examTip": "Tight RPO needs replication—continuous wins."
    },
    {
      "id": 8,
      "question": "A server’s BIOS doesn’t detect a new PCIe card despite proper seating and compatibility. What’s next?\n\nA. Verify the PCIe slot’s power allocation.\nB. Check the card’s firmware revision.\nC. Review the BIOS PCIe configuration.\nD. Assess the PSU’s wattage capacity.",
      "options": [
        "Verify the PCIe slot’s power allocation.",
        "Check the card’s firmware revision.",
        "Review the BIOS PCIe configuration.",
        "Assess the PSU’s wattage capacity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "BIOS PCIe settings might disable or misconfigure the slot, preventing detection. Power allocation, firmware, and PSU capacity matter but are less likely if the card isn’t seen at all.",
      "examTip": "BIOS blind to PCIe? Check slot settings—enablement first."
    },
    {
      "id": 9,
      "question": "A security audit reveals unauthorized entry attempts in server access logs. What physical control mitigates this?\n\nA. Add more CCTV surveillance cameras.\nB. Deploy biometric entry authentication.\nC. Increase frequency of guard patrols.\nD. Apply tamper-evident rack seals.",
      "options": [
        "Add more CCTV surveillance cameras.",
        "Deploy biometric entry authentication.",
        "Increase frequency of guard patrols.",
        "Apply tamper-evident rack seals."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Biometric authentication directly blocks unauthorized entry with unique identifiers. Cameras monitor, guards deter, and seals detect breaches, but only biometrics enforce access.",
      "examTip": "Physical breaches? Biometrics lock it down."
    },
    {
      "id": 10,
      "question": "A server’s network latency spikes during backups despite unsaturated 10GbE NICs. What’s the first check?\n\nA. Backup server’s CPU utilization.\nB. Server’s NIC teaming setup.\nC. Backup application’s throttling limits.\nD. Switch’s QoS prioritization rules.",
      "options": [
        "Backup server’s CPU utilization.",
        "Server’s NIC teaming setup.",
        "Backup application’s throttling limits.",
        "Switch’s QoS prioritization rules."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Backup apps often throttle bandwidth; misconfigured limits can spike latency. CPU usage, teaming, and QoS impact performance but are less tied to backup-specific latency jumps.",
      "examTip": "Backup latency? Throttling’s often the culprit."
    },
    {
      "id": 11,
      "question": "A Linux server’s ZFS file system reports corruption after a power outage. What ZFS feature should have prevented this?\n\nA. ZFS point-in-time snapshots.\nB. ZFS data integrity checksums.\nC. ZFS RAID-Z redundancy.\nD. ZFS inline deduplication.",
      "options": [
        "ZFS point-in-time snapshots.",
        "ZFS data integrity checksums.",
        "ZFS RAID-Z redundancy.",
        "ZFS inline deduplication."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ZFS checksums detect and correct corruption, safeguarding data integrity during outages. Snapshots save states, RAID-Z offers redundancy, and deduplication saves space—none prevent corruption directly.",
      "examTip": "ZFS corruption? Checksums save the day."
    },
    {
      "id": 12,
      "question": "A server won’t boot after a CMOS battery replacement, despite correct installation. What’s the likely issue?\n\nA. BIOS settings reset to factory defaults.\nB. The replacement battery is faulty.\nC. The PSU can’t sustain boot power.\nD. The RAID controller lost its config.",
      "options": [
        "BIOS settings reset to factory defaults.",
        "The replacement battery is faulty.",
        "The PSU can’t sustain boot power.",
        "The RAID controller lost its config."
      ],
      "correctAnswerIndex": 0,
      "explanation": "CMOS battery swaps reset BIOS to defaults, potentially breaking boot configs. A faulty battery, PSU issues, or RAID loss are less immediate unless additional symptoms appear.",
      "examTip": "CMOS change? Reconfigure BIOS—defaults disrupt."
    },
    {
      "id": 13,
      "question": "An active-passive cluster’s passive node takes over after a failure, but performance drops. What’s the probable cause?\n\nA. The passive node has lower resource specs.\nB. The heartbeat network is overloaded.\nC. Failover introduced processing delays.\nD. The passive node’s OS is out of date.",
      "options": [
        "The passive node has lower resource specs.",
        "The heartbeat network is overloaded.",
        "Failover introduced processing delays.",
        "The passive node’s OS is out of date."
      ],
      "correctAnswerIndex": 0,
      "explanation": "In active-passive setups, the passive node may have fewer resources, reducing performance under load. Heartbeat overload, failover delays, and OS versions affect failover, not sustained performance.",
      "examTip": "Passive node lags? Check its horsepower."
    },
    {
      "id": 14,
      "question": "A server’s iSCSI SAN connection drops during high I/O, with a stable network and healthy SAN. What’s first?\n\nA. iSCSI initiator timeout parameters.\nB. Server HBA firmware updates.\nC. SAN LUN masking settings.\nD. Network switch MTU alignment.",
      "options": [
        "iSCSI initiator timeout parameters.",
        "Server HBA firmware updates.",
        "SAN LUN masking settings.",
        "Network switch MTU alignment."
      ],
      "correctAnswerIndex": 0,
      "explanation": "High I/O can exceed default timeouts, dropping connections. Firmware, masking, and MTU issues are less sensitive to I/O spikes without other symptoms.",
      "examTip": "iSCSI drops under load? Extend timeouts."
    },
    {
      "id": 15,
      "question": "A DR plan requires a 4-hour RTO. What’s the most cost-effective site type?\n\nA. Hot site with synchronous replication.\nB. Warm site with daily backups.\nC. Cold site with weekly backups.\nD. Cloud site with asynchronous replication.",
      "options": [
        "Hot site with synchronous replication.",
        "Warm site with daily backups.",
        "Cold site with weekly backups.",
        "Cloud site with asynchronous replication."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Cloud with async replication meets 4-hour RTO at lower cost than a hot site. Hot sites are pricey, warm sites take longer, and cold sites need extensive setup.",
      "examTip": "Cost-effective DR? Cloud async is clutch."
    },
    {
      "id": 16,
      "question": "A server logs ‘out of memory’ errors despite ample RAM. What’s the first check?\n\nA. Application memory allocation limits.\nB. Server virtual memory settings.\nC. Hypervisor memory overprovisioning.\nD. BIOS memory mapping config.",
      "options": [
        "Application memory allocation limits.",
        "Server virtual memory settings.",
        "Hypervisor memory overprovisioning.",
        "BIOS memory mapping config."
      ],
      "correctAnswerIndex": 0,
      "explanation": "App-specific memory caps can trigger errors despite available RAM. Virtual memory, hypervisor overcommit, and BIOS affect system memory, not app limits.",
      "examTip": "Out of memory, RAM free? App caps are sneaky."
    },
    {
      "id": 17,
      "question": "A server’s Fibre Channel SAN link fails after a switch reboot, with working HBA and SAN. What’s first?\n\nA. Switch zoning configuration.\nB. HBA driver version.\nC. SAN LUN presentation rules.\nD. Server multipathing setup.",
      "options": [
        "Switch zoning configuration.",
        "HBA driver version.",
        "SAN LUN presentation rules.",
        "Server multipathing setup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A switch reboot might reset zoning, breaking connectivity. Drivers, LUN presentation, and multipathing are less likely to shift with a reboot.",
      "examTip": "FC fails post-reboot? Zoning resets are common."
    },
    {
      "id": 18,
      "question": "A server’s NIC teaming is set for load balancing, but traffic is uneven. What should you tweak?\n\nA. Switch to failover teaming mode.\nB. Adjust the load balancing algorithm.\nC. Modify the NIC MTU settings.\nD. Reconfigure switch port channels.",
      "options": [
        "Switch to failover teaming mode.",
        "Adjust the load balancing algorithm.",
        "Modify the NIC MTU settings.",
        "Reconfigure switch port channels."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The load balancing algorithm controls traffic distribution; tweaking it evens the load. Failover mode drops balancing, MTU affects packet size, and port channels need switch-side alignment.",
      "examTip": "Uneven teaming? Algorithm’s the lever."
    },
    {
      "id": 19,
      "question": "A Windows server’s PowerShell script fails with ‘command not found.’ What’s the first check?\n\nA. Script syntax accuracy.\nB. PowerShell execution policy.\nC. Server PATH variable.\nD. Script file permissions.",
      "options": [
        "Script syntax accuracy.",
        "PowerShell execution policy.",
        "Server PATH variable.",
        "Script file permissions."
      ],
      "correctAnswerIndex": 2,
      "explanation": "‘Command not found’ often means the command isn’t in PATH. Syntax errors differ, execution policy blocks running, and permissions deny access—not command lookup.",
      "examTip": "PS command missing? PATH’s the path."
    },
    {
      "id": 20,
      "question": "A server’s RAID 5 SSD array has slower-than-expected writes. What’s the likely cause?\n\nA. SSDs are read-optimized models.\nB. RAID controller cache is inadequate.\nC. Array is in degraded mode.\nD. CPU is throttling I/O processing.",
      "options": [
        "SSDs are read-optimized models.",
        "RAID controller cache is inadequate.",
        "Array is in degraded mode.",
        "CPU is throttling I/O processing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Insufficient RAID cache slows writes by forcing direct disk commits. Read-optimized SSDs, degraded arrays, and CPU throttling impact performance differently, not write-specific slowdowns.",
      "examTip": "RAID 5 writes lag? Cache is critical."
    },
    {
      "id": 21,
      "question": "A server’s firewall allows only essential ports, yet unauthorized access attempts continue. What’s next?\n\nA. Enable port knocking security.\nB. Deploy an intrusion detection system.\nC. Enhance firewall logging detail.\nD. Add MAC address filtering.",
      "options": [
        "Enable port knocking security.",
        "Deploy an intrusion detection system.",
        "Enhance firewall logging detail.",
        "Add MAC address filtering."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An IDS detects and alerts on unauthorized attempts, enhancing security. Port knocking hides services, logging tracks events, and MAC filtering limits devices—IDS is most proactive.",
      "examTip": "Attacks persist? IDS catches them."
    },
    {
      "id": 22,
      "question": "A server crashes intermittently from memory errors after RAM reseating. What’s next?\n\nA. Update BIOS firmware.\nB. Test RAM modules separately.\nC. Expand swap space allocation.\nD. Replace the motherboard.",
      "options": [
        "Update BIOS firmware.",
        "Test RAM modules separately.",
        "Expand swap space allocation.",
        "Replace the motherboard."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Testing RAM individually pinpoints faulty modules. BIOS updates, swap space, and motherboard swaps are broader fixes not directly isolating the issue.",
      "examTip": "Memory errors? Test sticks—one’s bad."
    },
    {
      "id": 23,
      "question": "A server’s VMs with bridged networking can’t reach external networks, but the host firewall allows all traffic. What’s the check?\n\nA. VM guest OS firewall rules.\nB. Hypervisor virtual switch config.\nC. Physical switch port security.\nD. Server NIC teaming setup.",
      "options": [
        "VM guest OS firewall rules.",
        "Hypervisor virtual switch config.",
        "Physical switch port security.",
        "Server NIC teaming setup."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Guest OS firewalls can block traffic despite host settings. Virtual switches, port security, and teaming affect connectivity but not if the host allows all.",
      "examTip": "VMs dark? Guest firewalls block inside."
    },
    {
      "id": 24,
      "question": "A server’s backups fail from insufficient target space with deduplication enabled. What’s first?\n\nA. Expand backup target capacity.\nB. Shorten retention period.\nC. Disable deduplication feature.\nD. Compress backup data streams.",
      "options": [
        "Expand backup target capacity.",
        "Shorten retention period.",
        "Disable deduplication feature.",
        "Compress backup data streams."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Shortening retention frees space by purging old backups. Expanding capacity costs more, disabling dedup wastes space, and compression may not suffice.",
      "examTip": "Backup full? Cut retention—space saver."
    },
    {
      "id": 25,
      "question": "A server’s ping to a remote host fails, but tracert reaches the last hop. What’s the issue?\n\nA. Remote host firewall blocks ICMP.\nB. Server gateway is misconfigured.\nC. Network switch drops packets.\nD. DNS resolution is failing.",
      "options": [
        "Remote host firewall blocks ICMP.",
        "Server gateway is misconfigured.",
        "Network switch drops packets.",
        "DNS resolution is failing."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Tracert reaching the last hop but ping failing suggests the remote host blocks ICMP. Gateway, switch, or DNS issues would halt tracert earlier.",
      "examTip": "Ping fails, tracert flies? Firewall’s thewall."
    },
    {
      "id": 26,
      "question": "A server’s disk IOPS are maxed, but CPU and RAM are idle. What’s the first upgrade?\n\nA. Boost server CPU cores.\nB. Add server RAM capacity.\nC. Switch storage to NVMe drives.\nD. Upgrade network to 25GbE.",
      "options": [
        "Boost server CPU cores.",
        "Add server RAM capacity.",
        "Switch storage to NVMe drives.",
        "Upgrade network to 25GbE."
      ],
      "correctAnswerIndex": 2,
      "explanation": "NVMe drives vastly increase IOPS, fixing the bottleneck. CPU, RAM, and network upgrades don’t directly address disk I/O limits.",
      "examTip": "IOPS pegged? NVMe’s the speed king."
    },
    {
      "id": 27,
      "question": "A server room’s access system fails, allowing free entry. What’s the best temporary fix?\n\nA. Station guards at the door.\nB. Add locks to server racks.\nC. Disconnect servers from networks.\nD. Shut down non-essential servers.",
      "options": [
        "Station guards at the door.",
        "Add locks to server racks.",
        "Disconnect servers from networks.",
        "Shut down non-essential servers."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Guards enforce immediate access control. Rack locks, disconnection, and shutdowns are less comprehensive or more disruptive.",
      "examTip": "Access down? Guards hold the line."
    },
    {
      "id": 28,
      "question": "A server’s RAID 6 array loses three drives at once. What’s the impact?\n\nA. Array runs with reduced performance.\nB. Array stays accessible in critical mode.\nC. Array fails with total data loss.\nD. Array rebuilds using dual parity.",
      "options": [
        "Array runs with reduced performance.",
        "Array stays accessible in critical mode.",
        "Array fails with total data loss.",
        "Array rebuilds using dual parity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 6 tolerates two drive failures; three exceeds this, causing failure and data loss. Performance drops or critical mode occur with fewer failures; rebuilding needs spares.",
      "examTip": "RAID 6 stops at two—three’s a KO."
    },
    {
      "id": 29,
      "question": "A server’s HTTPS app triggers client certificate warnings. What’s the first check?\n\nA. Server’s system time and date.\nB. Certificate’s validity period.\nC. Server’s IP settings.\nD. Client browser compatibility.",
      "options": [
        "Server’s system time and date.",
        "Certificate’s validity period.",
        "Server’s IP settings.",
        "Client browser compatibility."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Incorrect server time can make certificates appear invalid. Expiration, IP mismatches, and browser issues follow if time is correct.",
      "examTip": "Cert warnings? Time’s the first tick."
    },
    {
      "id": 30,
      "question": "A server’s fans run at max despite normal temps. What’s the first check?\n\nA. BIOS fan control settings.\nB. Temperature sensor calibration.\nC. PSU power consistency.\nD. Internal dust buildup.",
      "options": [
        "BIOS fan control settings.",
        "Temperature sensor calibration.",
        "PSU power consistency.",
        "Internal dust buildup."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Faulty sensors can misreport temps, driving fans to max. BIOS settings, PSU, and dust affect cooling but not directly fan behavior if temps are normal.",
      "examTip": "Fans scream, temps cool? Sensors fib."
    },
    {
      "id": 31,
      "question": "A server’s per-core licensed app runs poorly with many cores. What’s the fix?\n\nA. Switch to per-socket licensing.\nB. Optimize app for multi-core use.\nC. Reduce licensed core count.\nD. Upgrade to higher-clocked cores.",
      "options": [
        "Switch to per-socket licensing.",
        "Optimize app for multi-core use.",
        "Reduce licensed core count.",
        "Upgrade to higher-clocked cores."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Optimizing the app for multi-core improves performance without licensing changes. Per-socket shifts cost, fewer cores limit scaling, and faster cores don’t fix app design.",
      "examTip": "App chokes on cores? Optimize it."
    },
    {
      "id": 32,
      "question": "A server’s OS install fails with ‘hardware unsupported,’ but it’s on the HCL. What’s next?\n\nA. Verify install media integrity.\nB. Check BIOS version compatibility.\nC. Update hardware firmware.\nD. Review install config options.",
      "options": [
        "Verify install media integrity.",
        "Check BIOS version compatibility.",
        "Update hardware firmware.",
        "Review install config options."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Outdated firmware can break OS support despite HCL listing. Media, BIOS, and config issues are less likely if hardware isn’t current.",
      "examTip": "HCL ok, still fails? Firmware’s the fix."
    },
    {
      "id": 33,
      "question": "A server’s synchronous replication fails due to network latency. What’s the solution?\n\nA. Boost network bandwidth.\nB. Switch to asynchronous replication.\nC. Relax the RPO target.\nD. Deploy WAN acceleration.",
      "options": [
        "Boost network bandwidth.",
        "Switch to asynchronous replication.",
        "Relax the RPO target.",
        "Deploy WAN acceleration."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Async replication tolerates latency unlike sync, which needs instant acknowledgment. Bandwidth, RPO tweaks, and acceleration help but don’t fix latency directly.",
      "examTip": "Sync hates lag—go async."
    },
    {
      "id": 34,
      "question": "A server’s virtual switch stops traffic after a hypervisor update, with working NICs. What’s first?\n\nA. Virtual switch VLAN settings.\nB. Hypervisor network driver match.\nC. VM guest OS network config.\nD. Physical switch spanning tree.",
      "options": [
        "Virtual switch VLAN settings.",
        "Hypervisor network driver match.",
        "VM guest OS network config.",
        "Physical switch spanning tree."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An update might break driver compatibility, halting the virtual switch. VLANs, guest OS, and spanning tree are less likely post-update culprits.",
      "examTip": "Update kills networking? Drivers drift."
    },
    {
      "id": 35,
      "question": "A server’s drives need secure erasure before decommissioning. What ensures no recovery?\n\nA. Quick format with single overwrite.\nB. Multi-pass disk wiping.\nC. Degaussing disk platters.\nD. Physical drive destruction.",
      "options": [
        "Quick format with single overwrite.",
        "Multi-pass disk wiping.",
        "Degaussing disk platters.",
        "Physical drive destruction."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Physical destruction guarantees no data recovery by ruining the drive. Formatting, wiping, and degaussing reduce recoverability but aren’t absolute.",
      "examTip": "Total erasure? Smash it—done."
    },
    {
      "id": 36,
      "question": "A server’s app slows after enabling encryption. What mitigates this?\n\nA. Upgrade server CPU power.\nB. Offload encryption to hardware.\nC. Boost app memory allocation.\nD. Trim unnecessary services.",
      "options": [
        "Upgrade server CPU power.",
        "Offload encryption to hardware.",
        "Boost app memory allocation.",
        "Trim unnecessary services."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hardware offload (e.g., AES-NI) cuts CPU load from encryption. CPU upgrades cost more, memory and services don’t target encryption overhead.",
      "examTip": "Encryption drags? Hardware lifts."
    },
    {
      "id": 37,
      "question": "A server’s Cat6a cables support 10GbE, but it runs at 1GbE. What’s first?\n\nA. NIC speed and duplex settings.\nB. Switch port speed config.\nC. Cable length and integrity.\nD. BIOS network settings.",
      "options": [
        "NIC speed and duplex settings.",
        "Switch port speed config.",
        "Cable length and integrity.",
        "BIOS network settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIC settings might lock to 1GbE, ignoring cable potential. Switch ports, cables, and BIOS are next if NIC is set right.",
      "examTip": "Stuck at 1GbE? NIC’s the choke."
    },
    {
      "id": 38,
      "question": "A server’s RAID controller battery dies, switching to write-through. What’s the immediate effect?\n\nA. Write speed drops significantly.\nB. Read speed improves slightly.\nC. Array goes offline temporarily.\nD. Data integrity risks increase.",
      "options": [
        "Write speed drops significantly.",
        "Read speed improves slightly.",
        "Array goes offline temporarily.",
        "Data integrity risks increase."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Write-through skips cache, slowing writes. Reads stay unaffected, the array remains online, and integrity isn’t directly at risk.",
      "examTip": "Battery out, writes crawl—cache counts."
    },
    {
      "id": 39,
      "question": "A server’s RBAC gives users excess permissions. What’s the first audit?\n\nA. User account configurations.\nB. Role definitions and mappings.\nC. Group policy assignments.\nD. File system access lists.",
      "options": [
        "User account configurations.",
        "Role definitions and mappings.",
        "Group policy assignments.",
        "File system access lists."
      ],
      "correctAnswerIndex": 1,
      "explanation": "RBAC ties permissions to roles; auditing definitions and assignments catches errors. Users, GPOs, and ACLs follow if roles are off.",
      "examTip": "RBAC overreach? Roles reign."
    },
    {
      "id": 40,
      "question": "A server’s SAN performance dips at peak with multipathing enabled. What’s first?\n\nA. SAN disk queue depth.\nB. HBA load balancing setup.\nC. Network latency metrics.\nD. SAN cache utilization.",
      "options": [
        "SAN disk queue depth.",
        "HBA load balancing setup.",
        "Network latency metrics.",
        "SAN cache utilization."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Poor HBA load balancing can overload paths during peaks. Queues, latency, and cache impact performance but tie to multipathing less directly.",
      "examTip": "SAN slows? Balance HBAs—paths matter."
    },
    {
      "id": 41,
      "question": "A server uses synthetic full backups. What’s the main benefit?\n\nA. Less storage consumption.\nB. Quicker backup creation.\nC. Easier restore process.\nD. Reduced network load.",
      "options": [
        "Less storage consumption.",
        "Quicker backup creation.",
        "Easier restore process.",
        "Reduced network load."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Synthetic fulls merge incrementals into one file, simplifying restores. Storage, speed, and network benefits are secondary.",
      "examTip": "Synthetic fulls? Restore’s a breeze."
    },
    {
      "id": 42,
      "question": "A server’s RAID 1 loses one drive. What’s the first step before replacement?\n\nA. Initiate array rebuild process.\nB. Back up remaining drive data.\nC. Update RAID firmware.\nD. Check failed drive’s SMART data.",
      "options": [
        "Initiate array rebuild process.",
        "Back up remaining drive data.",
        "Update RAID firmware.",
        "Check failed drive’s SMART data."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Backing up protects against a second failure during rebuild. Rebuilding risks data, firmware isn’t urgent, and SMART is diagnostic.",
      "examTip": "RAID 1 down? Backup trumps rebuild."
    },
    {
      "id": 43,
      "question": "A server’s tracert shows high latency at hop 3 to a remote host. What’s indicated?\n\nA. Server NIC is malfunctioning.\nB. Remote host is overloaded.\nC. Network path has congestion.\nD. DNS lookup is delayed.",
      "options": [
        "Server NIC is malfunctioning.",
        "Remote host is overloaded.",
        "Network path has congestion.",
        "DNS lookup is delayed."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Latency at hop 3 points to congestion on that segment. NIC, host overload, and DNS would affect all hops or resolution.",
      "examTip": "Tracert lags mid-path? Network’s clogged."
    },
    {
      "id": 44,
      "question": "A server’s VM won’t start after a snapshot revert. What’s first?\n\nA. Virtual disk file integrity.\nB. Hypervisor resource limits.\nC. Snapshot creation timestamp.\nD. Guest OS version compatibility.",
      "options": [
        "Virtual disk file integrity.",
        "Hypervisor resource limits.",
        "Snapshot creation timestamp.",
        "Guest OS version compatibility."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corrupted virtual disks from a revert can block startup. Resources, timestamps, and OS versions are less likely startup killers.",
      "examTip": "VM dead post-revert? Disk’s suspect."
    },
    {
      "id": 45,
      "question": "A server room’s power drops voltage during peak use. What fixes this?\n\nA. UPS with voltage regulation.\nB. Upgrade server PSU ratings.\nC. Cap server power usage.\nD. Add redundant power feeds.",
      "options": [
        "UPS with voltage regulation.",
        "Upgrade server PSU ratings.",
        "Cap server power usage.",
        "Add redundant power feeds."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A UPS with AVR stabilizes voltage drops. PSU upgrades, capping, and redundancy don’t regulate incoming power.",
      "examTip": "Voltage dips? AVR steadies it."
    },
    {
      "id": 46,
      "question": "A server’s RAID 10 loses two drives in separate mirror sets. What’s the status?\n\nA. Fully operational array.\nB. Degraded but functional array.\nC. Complete array failure.\nD. Read-only array mode.",
      "options": [
        "Fully operational array.",
        "Degraded but functional array.",
        "Complete array failure.",
        "Read-only array mode."
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 10 survives one failure per mirror; two in separate sets degrades but runs. Same-set losses kill it; read-only isn’t standard.",
      "examTip": "RAID 10 takes one per mirror—layout’s key."
    },
    {
      "id": 47,
      "question": "A server’s SNMPv3 fails authentication. What’s the first check?\n\nA. SNMP community string config.\nB. Encryption key settings.\nC. User credential details.\nD. Trap destination address.",
      "options": [
        "SNMP community string config.",
        "Encryption key settings.",
        "User credential details.",
        "Trap destination address."
      ],
      "correctAnswerIndex": 2,
      "explanation": "SNMPv3 uses user-based auth; wrong credentials fail it. Community strings are v1/v2, keys encrypt, and traps alert—not auth.",
      "examTip": "SNMPv3 auth flops? Users rule."
    },
    {
      "id": 48,
      "question": "A server’s performance dips during backups from SAN saturation. What helps?\n\nA. Boost SAN bandwidth capacity.\nB. Apply backup throttling controls.\nC. Upgrade server CPU power.\nD. Increase server RAM size.",
      "options": [
        "Boost SAN bandwidth capacity.",
        "Apply backup throttling controls.",
        "Upgrade server CPU power.",
        "Increase server RAM size."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Throttling limits backup load on the SAN, easing saturation. Bandwidth costs more, CPU and RAM don’t fix SAN bottlenecks.",
      "examTip": "SAN swamped? Throttle backups—pace it."
    },
    {
      "id": 49,
      "question": "A server’s asset tag is missing during an audit. What confirms its identity?\n\nA. Network topology charts.\nB. Asset inventory database.\nC. DR plan documentation.\nD. Performance baseline logs.",
      "options": [
        "Network topology charts.",
        "Asset inventory database.",
        "DR plan documentation.",
        "Performance baseline logs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asset inventory tracks hardware details like tags. Topology, DR plans, and baselines focus elsewhere.",
      "examTip": "Tag gone? Inventory knows."
    },
    {
      "id": 50,
      "question": "A server’s NTP sync fails despite UDP 123 being open. What’s next?\n\nA. NTP server reachability.\nB. Server time zone setting.\nC. Network DNS resolution.\nD. NTP client configuration.",
      "options": [
        "NTP server reachability.",
        "Server time zone setting.",
        "Network DNS resolution.",
        "NTP client configuration."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If UDP 123 is open, the NTP server might be down or unreachable. Time zones, DNS, and client config follow if the server can’t respond.",
      "examTip": "NTP off, port on? Server’s AWOL."
    },
    {
      "id": 51,
      "question": "A server’s RAID 10 array with four drives experiences a drive failure. Immediately after, another drive fails in a different mirror set. What is the array’s status?\n\nA. The array remains fully operational.\nB. The array enters a degraded state but remains accessible.\nC. The array fails completely, and data is lost.\nD. The array automatically rebuilds using hot spares.",
      "options": [
        "The array remains fully operational.",
        "The array enters a degraded state but remains accessible.",
        "The array fails completely, and data is lost.",
        "The array automatically rebuilds using hot spares."
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 10 combines mirroring and striping. Losing one drive per mirror set (e.g., one from each of two sets) leaves the array operational but degraded, with no redundancy. Total failure occurs only if both drives in a single mirror set fail. Rebuilding requires spares and manual intervention.",
      "examTip": "RAID 10 survives one failure per mirror—layout is key."
    },
    {
      "id": 52,
      "question": "A server’s performance monitor shows high CPU utilization but low RAM usage. Which upgrade would most directly address this?\n\nA. Adding more RAM modules.\nB. Installing faster SSDs.\nC. Upgrading to a CPU with higher clock speed.\nD. Increasing the PSU’s wattage rating.",
      "options": [
        "Adding more RAM modules.",
        "Installing faster SSDs.",
        "Upgrading to a CPU with higher clock speed.",
        "Increasing the PSU’s wattage rating."
      ],
      "correctAnswerIndex": 2,
      "explanation": "High CPU utilization with low RAM usage points to a CPU bottleneck. Upgrading to a CPU with higher clock speed or more cores directly alleviates this. RAM, SSDs, or PSU upgrades target different issues, not CPU constraints.",
      "examTip": "CPU maxed, RAM free? Speed up the core."
    },
    {
      "id": 53,
      "question": "A server’s network connection drops during high traffic periods, despite NIC teaming with link aggregation. What should you investigate first?\n\nA. Switch port saturation on the team’s uplink.\nB. Server’s NIC driver compatibility.\nC. Switch’s spanning tree configuration.\nD. Server’s firewall rules blocking traffic.",
      "options": [
        "Switch port saturation on the team’s uplink.",
        "Server’s NIC driver compatibility.",
        "Switch’s spanning tree configuration.",
        "Server’s firewall rules blocking traffic."
      ],
      "correctAnswerIndex": 0,
      "explanation": "High traffic can overwhelm the switch’s uplink, causing drops despite teaming. NIC drivers, spanning tree, or firewall issues are less likely to cause intermittent drops tied to traffic peaks.",
      "examTip": "Teaming fails under load? Uplink’s swamped."
    },
    {
      "id": 54,
      "question": "A disaster recovery plan specifies a 1-hour RTO for a critical server. Which site type best meets this requirement?\n\nA. Hot site with real-time replication.\nB. Warm site with daily backups.\nC. Cold site with off-site tapes.\nD. Cloud site with hourly snapshots.",
      "options": [
        "Hot site with real-time replication.",
        "Warm site with daily backups.",
        "Cold site with off-site tapes.",
        "Cloud site with hourly snapshots."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A hot site with real-time replication enables near-instant failover, meeting a 1-hour RTO. Warm sites, cold sites, and cloud snapshots require more time for restoration or synchronization.",
      "examTip": "Short RTO? Hot site’s primed."
    },
    {
      "id": 55,
      "question": "A server’s PSU fan is overheating, but the server operates normally. What should you do first?\n\nA. Replace the PSU immediately.\nB. Monitor PSU temperature trends.\nC. Increase server room cooling capacity.\nD. Update the PSU’s firmware settings.",
      "options": [
        "Replace the PSU immediately.",
        "Monitor PSU temperature trends.",
        "Increase server room cooling capacity.",
        "Update the PSU’s firmware settings."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Monitoring PSU temperature trends assesses if overheating is consistent or temporary, informing next steps. Replacing the PSU, boosting room cooling, or updating firmware lacks data justification initially.",
      "examTip": "PSU fan hot? Track it first."
    },
    {
      "id": 56,
      "question": "A server’s SSH access fails with ‘connection refused’ after a security update. What’s the first check?\n\nA. SSH service status on the server.\nB. Server firewall rules post-update.\nC. SSH client configuration settings.\nD. Network switch port security.",
      "options": [
        "SSH service status on the server.",
        "Server firewall rules post-update.",
        "SSH client configuration settings.",
        "Network switch port security."
      ],
      "correctAnswerIndex": 0,
      "explanation": "‘Connection refused’ typically means the SSH service isn’t running or listening on the expected port. Firewall rules, client settings, or switch security might block access but usually yield different errors.",
      "examTip": "SSH refused? Check if it’s alive."
    },
    {
      "id": 57,
      "question": "A server’s SAS drives in RAID 5 show degraded performance after adding a new drive. What’s the likely cause?\n\nA. The new drive has a different rotational speed.\nB. The RAID array is in rebuild mode.\nC. The SAS controller is overloaded.\nD. The drives have mismatched firmware versions.",
      "options": [
        "The new drive has a different rotational speed.",
        "The RAID array is in rebuild mode.",
        "The SAS controller is overloaded.",
        "The drives have mismatched firmware versions."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Adding a drive initiates a rebuild, which increases I/O load and slows performance. Speed mismatches, controller overload, or firmware issues are less immediate without specific evidence.",
      "examTip": "RAID lags after add? Rebuild’s running."
    },
    {
      "id": 58,
      "question": "A server’s IP configuration is correct, but it can’t reach the gateway. What’s the first step?\n\nA. Check the server’s subnet mask.\nB. Verify the gateway’s status.\nC. Test the server’s NIC with loopback.\nD. Inspect the network cable integrity.",
      "options": [
        "Check the server’s subnet mask.",
        "Verify the gateway’s status.",
        "Test the server’s NIC with loopback.",
        "Inspect the network cable integrity."
      ],
      "correctAnswerIndex": 3,
      "explanation": "A broken cable prevents gateway communication despite correct settings. Subnet masks, gateway status, and NIC functionality are subsequent checks after ensuring physical connectivity.",
      "examTip": "Gateway lost? Cable’s first."
    },
    {
      "id": 59,
      "question": "A server’s backup strategy uses weekly full and daily differential backups. How many restores are needed after a Wednesday failure?\n\nA. 1\nB. 2\nC. 3\nD. 4",
      "options": [
        "1",
        "2",
        "3",
        "4"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Restoring requires the last full backup (e.g., Sunday) and the latest differential (Tuesday), totaling two steps. Differentials cover all changes since the full backup, unlike incrementals.",
      "examTip": "Differentials mean two restores."
    },
    {
      "id": 60,
      "question": "A server rack’s cooling efficiency drops despite clean filters and functional fans. What should you check?\n\nA. Server density and heat output.\nB. Rack door alignment and seals.\nC. Internal cable management.\nD. PDU load balancing.",
      "options": [
        "Server density and heat output.",
        "Rack door alignment and seals.",
        "Internal cable management.",
        "PDU load balancing."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Increased server density raises heat output, overwhelming cooling capacity. Door seals, cabling, and PDU balancing impact airflow or power, not cooling efficiency directly.",
      "examTip": "Cooling fades? Density’s heating."
    },
    {
      "id": 61,
      "question": "A server’s application experiences timeouts during peak hours. What should you monitor first?\n\nA. Network latency metrics.\nB. Disk I/O wait times.\nC. Memory paging rates.\nD. CPU ready queue length.",
      "options": [
        "Network latency metrics.",
        "Disk I/O wait times.",
        "Memory paging rates.",
        "CPU ready queue length."
      ],
      "correctAnswerIndex": 3,
      "explanation": "High CPU ready queues indicate contention, delaying processes and causing timeouts. Network, disk, and memory issues can contribute, but CPU contention is a primary peak-hour culprit.",
      "examTip": "Peak timeouts? CPU’s queued."
    },
    {
      "id": 62,
      "question": "A server’s RAID 5 array with SSDs shows slower write performance than expected. What’s the probable cause?\n\nA. SSDs are not enterprise-grade.\nB. RAID controller lacks write-back cache.\nC. Array is configured with small stripe size.\nD. SSDs are connected via SATA instead of SAS.",
      "options": [
        "SSDs are not enterprise-grade.",
        "RAID controller lacks write-back cache.",
        "Array is configured with small stripe size.",
        "SSDs are connected via SATA instead of SAS."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Without write-back cache, RAID 5 writes are slower due to immediate parity calculations. Non-enterprise SSDs, small stripes, or SATA connections affect performance less directly.",
      "examTip": "RAID 5 SSD slow? Cache’s missing."
    },
    {
      "id": 63,
      "question": "A server’s BIOS logs a ‘thermal event’ but the server continues running. What should you do first?\n\nA. Replace the CPU immediately.\nB. Check the server’s cooling system.\nC. Update the BIOS firmware.\nD. Increase the server’s power limit.",
      "options": [
        "Replace the CPU immediately.",
        "Check the server’s cooling system.",
        "Update the BIOS firmware.",
        "Increase the server’s power limit."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A thermal event suggests cooling failure; inspecting fans or heat sinks prevents escalation. CPU replacement, BIOS updates, or power adjustments are secondary without cooling confirmation.",
      "examTip": "Thermal log? Cool it first."
    },
    {
      "id": 64,
      "question": "A server’s network configuration uses DHCP, but it receives an APIPA address. What’s the first check?\n\nA. DHCP server availability.\nB. Server’s NIC driver version.\nC. Network switch VLAN settings.\nD. Server’s firewall rules.",
      "options": [
        "DHCP server availability.",
        "Server’s NIC driver version.",
        "Network switch VLAN settings.",
        "Server’s firewall rules."
      ],
      "correctAnswerIndex": 0,
      "explanation": "An APIPA address (169.254.x.x) indicates DHCP failure, so checking the DHCP server’s status is critical. NIC drivers, VLANs, or firewalls don’t directly trigger APIPA.",
      "examTip": "APIPA shows? DHCP’s offline."
    },
    {
      "id": 65,
      "question": "A server’s SAN connection fails after a firmware update on the SAN switch. What should you rollback first?\n\nA. Server’s HBA drivers.\nB. SAN switch firmware.\nC. Server’s BIOS version.\nD. SAN array firmware.",
      "options": [
        "Server’s HBA drivers.",
        "SAN switch firmware.",
        "Server’s BIOS version.",
        "SAN array firmware."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Rolling back the SAN switch firmware addresses the change that broke connectivity. HBA drivers, BIOS, or array firmware updates are less likely culprits.",
      "examTip": "SAN drops post-switch? Undo it."
    },
    {
      "id": 66,
      "question": "A server’s VM snapshot fails to consolidate, consuming excessive storage. What’s the first step?\n\nA. Delete unused snapshots.\nB. Increase VM’s disk space.\nC. Revert to a previous snapshot.\nD. Check hypervisor logs for errors.",
      "options": [
        "Delete unused snapshots.",
        "Increase VM’s disk space.",
        "Revert to a previous snapshot.",
        "Check hypervisor logs for errors."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Hypervisor logs pinpoint why consolidation fails (e.g., corruption, permissions). Deleting snapshots, increasing space, or reverting risks data without understanding the issue.",
      "examTip": "Snapshot won’t consolidate? Logs explain."
    },
    {
      "id": 67,
      "question": "A server’s RAID array rebuild is taking longer than expected. What should you check first?\n\nA. RAID controller’s rebuild priority setting.\nB. Disk I/O activity from other operations.\nC. RAID stripe size configuration.\nD. Server’s CPU utilization levels.",
      "options": [
        "RAID controller’s rebuild priority setting.",
        "Disk I/O activity from other operations.",
        "RAID stripe size configuration.",
        "Server’s CPU utilization levels."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Low rebuild priority allocates fewer resources, slowing the process. I/O activity, stripe size, or CPU usage impact performance but not rebuild speed as directly.",
      "examTip": "Rebuild drags? Priority sets pace."
    },
    {
      "id": 68,
      "question": "A server room’s access logs show unauthorized entry attempts during off-hours. What should you implement?\n\nA. Increase camera coverage.\nB. Add two-factor authentication.\nC. Schedule random guard patrols.\nD. Install motion-activated lights.",
      "options": [
        "Increase camera coverage.",
        "Add two-factor authentication.",
        "Schedule random guard patrols.",
        "Install motion-activated lights."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Two-factor authentication (2FA) enforces stricter access control, preventing unauthorized entry. Cameras, patrols, and lights deter or detect but don’t secure entry directly.",
      "examTip": "Intruders knocking? 2FA locks."
    },
    {
      "id": 69,
      "question": "A server’s iSCSI performance degrades during backups, with high latency on the SAN. What’s the first adjustment?\n\nA. Increase iSCSI timeout values.\nB. Enable jumbo frames on the network.\nC. Throttle backup bandwidth usage.\nD. Upgrade the server’s NIC to 10GbE.",
      "options": [
        "Increase iSCSI timeout values.",
        "Enable jumbo frames on the network.",
        "Throttle backup bandwidth usage.",
        "Upgrade the server’s NIC to 10GbE."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Throttling backups reduces SAN contention, lowering latency. Timeouts, jumbo frames, or NIC upgrades mitigate symptoms but don’t address backup-induced load directly.",
      "examTip": "Backup slows SAN? Cap its flow."
    },
    {
      "id": 70,
      "question": "A server’s backup strategy uses monthly full and daily incremental backups. How many restores are needed after a failure on the 15th?\n\nA. 1\nB. 2\nC. 15\nD. 16",
      "options": [
        "1",
        "2",
        "15",
        "16"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Restoring requires the last full backup (1st) and all incrementals (2nd–15th), totaling 16 steps. Incrementals build sequentially, unlike differentials.",
      "examTip": "Incrementals stack—count them all."
    },
    {
      "id": 71,
      "question": "A server’s NIC teaming is configured for load balancing, but one NIC is overloaded. What should you adjust?\n\nA. Switch to failover teaming mode.\nB. Change the load balancing algorithm.\nC. Modify the NIC’s MTU settings.\nD. Reconfigure switch port channels.",
      "options": [
        "Switch to failover teaming mode.",
        "Change the load balancing algorithm.",
        "Modify the NIC’s MTU settings.",
        "Reconfigure switch port channels."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Adjusting the load balancing algorithm (e.g., from IP hash to round-robin) redistributes traffic evenly. Failover mode abandons balancing, MTU tweaks packet size, and port channels need switch-side changes.",
      "examTip": "NIC team uneven? Tune the split."
    },
    {
      "id": 72,
      "question": "A server’s CPU overheats despite functional fans. What’s the first check?\n\nA. Thermal paste application.\nB. BIOS fan control settings.\nC. Server room temperature.\nD. CPU voltage settings.",
      "options": [
        "Thermal paste application.",
        "BIOS fan control settings.",
        "Server room temperature.",
        "CPU voltage settings."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Degraded thermal paste hinders heat transfer, causing CPU overheating. BIOS settings, room temp, or voltage adjustments are less immediate causes.",
      "examTip": "CPU hot, fans on? Paste’s worn."
    },
    {
      "id": 73,
      "question": "A server’s application crashes with ‘segmentation fault’ errors. What’s the probable cause?\n\nA. Memory corruption or access violation.\nB. Disk I/O timeouts.\nC. Network packet loss.\nD. CPU scheduling conflicts.",
      "options": [
        "Memory corruption or access violation.",
        "Disk I/O timeouts.",
        "Network packet loss.",
        "CPU scheduling conflicts."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Segmentation faults stem from memory issues like invalid pointers or corruption. Disk, network, or CPU problems produce distinct errors.",
      "examTip": "Segfault crash? Memory’s culprit."
    },
    {
      "id": 74,
      "question": "A server’s RAID 0 array loses one drive. What’s the impact?\n\nA. Array remains accessible with reduced performance.\nB. Array enters read-only mode.\nC. Array fails completely, and data is lost.\nD. Array automatically rebuilds using parity.",
      "options": [
        "Array remains accessible with reduced performance.",
        "Array enters read-only mode.",
        "Array fails completely, and data is lost.",
        "Array automatically rebuilds using parity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 0 lacks redundancy; one drive failure collapses the array, losing all data. Other options apply to fault-tolerant RAID levels.",
      "examTip": "RAID 0 breaks? All’s lost."
    },
    {
      "id": 75,
      "question": "A server’s VM fails to boot after a guest OS update. What should you check first?\n\nA. VM’s virtual hardware version.\nB. Hypervisor compatibility matrix.\nC. Guest OS kernel panic logs.\nD. VM’s snapshot history.",
      "options": [
        "VM’s virtual hardware version.",
        "Hypervisor compatibility matrix.",
        "Guest OS kernel panic logs.",
        "VM’s snapshot history."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Kernel panic logs detail why the guest OS crashed post-update. Hardware version, compatibility, or snapshots are less immediate without boot failure specifics.",
      "examTip": "VM dead after update? Kernel logs it."
    },
    {
      "id": 76,
      "question": "A server’s NTP sync fails with ‘server not responding.’ What’s the first check?\n\nA. NTP server firewall rules.\nB. Server’s NTP client configuration.\nC. Network path connectivity.\nD. NTP server’s time accuracy.",
      "options": [
        "NTP server firewall rules.",
        "Server’s NTP client configuration.",
        "Network path connectivity.",
        "NTP server’s time accuracy."
      ],
      "correctAnswerIndex": 2,
      "explanation": "‘Server not responding’ suggests a network issue; verifying connectivity (e.g., ping) ensures reachability. Firewall, client config, or time accuracy checks follow if connectivity fails.",
      "examTip": "NTP silent? Path’s cut."
    },
    {
      "id": 77,
      "question": "A server’s RAID 6 array with six drives loses three drives. What’s the status?\n\nA. Array remains functional with reduced performance.\nB. Array enters a critical state but remains accessible.\nC. Array fails completely, and data is lost.\nD. Array automatically rebuilds using dual parity.",
      "options": [
        "Array remains functional with reduced performance.",
        "Array enters a critical state but remains accessible.",
        "Array fails completely, and data is lost.",
        "Array automatically rebuilds using dual parity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 6 withstands two drive failures; three exceeds its dual parity, causing complete failure. Other states apply to fewer losses; rebuilding needs spares.",
      "examTip": "RAID 6 caps at two—three kills."
    },
    {
      "id": 78,
      "question": "A server’s SAN performance improves after disabling jumbo frames. Why?\n\nA. Reduced CPU overhead from packet processing.\nB. Elimination of MTU mismatch issues.\nC. Increased network bandwidth availability.\nD. Improved disk I/O throughput.",
      "options": [
        "Reduced CPU overhead from packet processing.",
        "Elimination of MTU mismatch issues.",
        "Increased network bandwidth availability.",
        "Improved disk I/O throughput."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Disabling jumbo frames likely resolved an MTU mismatch, reducing fragmentation and boosting SAN performance. CPU overhead, bandwidth, or I/O gains are less direct effects.",
      "examTip": "Jumbo off helps? MTU aligned."
    },
    {
      "id": 79,
      "question": "A server’s virtual machine experiences high memory ballooning. What should you adjust?\n\nA. Increase the VM’s memory reservation.\nB. Decrease the VM’s memory limit.\nC. Add more physical RAM to the host.\nD. Reduce the number of vCPUs assigned.",
      "options": [
        "Increase the VM’s memory reservation.",
        "Decrease the VM’s memory limit.",
        "Add more physical RAM to the host.",
        "Reduce the number of vCPUs assigned."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Increasing memory reservation ensures the VM gets dedicated RAM, reducing ballooning. Lowering limits restricts usage, adding RAM helps broadly, and vCPUs don’t affect memory directly.",
      "examTip": "Ballooning high? Reserve more."
    },
    {
      "id": 80,
      "question": "A server’s BIOS update fails with a checksum error. What should you do first?\n\nA. Re-download the BIOS update file.\nB. Replace the CMOS battery.\nC. Reset BIOS settings to defaults.\nD. Check the server’s PSU stability.",
      "options": [
        "Re-download the BIOS update file.",
        "Replace the CMOS battery.",
        "Reset BIOS settings to defaults.",
        "Check the server’s PSU stability."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A checksum error indicates a corrupted file; re-downloading ensures integrity. Battery, settings, or PSU issues don’t typically cause checksum failures.",
      "examTip": "Checksum flops? File’s bad."
    },
    {
      "id": 81,
      "question": "A server’s application uses a proxy server for external access. What’s the primary benefit?\n\nA. Reduced network latency.\nB. Enhanced security through filtering.\nC. Increased storage capacity.\nD. Improved CPU performance.",
      "options": [
        "Reduced network latency.",
        "Enhanced security through filtering.",
        "Increased storage capacity.",
        "Improved CPU performance."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Proxies filter and control traffic, boosting security. Latency, storage, or CPU benefits aren’t primary proxy functions.",
      "examTip": "Proxy perk? Security leads."
    },
    {
      "id": 82,
      "question": "A server’s RAID 1 array with two drives experiences a drive failure. What’s the operational impact?\n\nA. Array remains fully operational.\nB. Array enters a degraded state but remains accessible.\nC. Array fails completely, and data is lost.\nD. Array automatically rebuilds using parity.",
      "options": [
        "Array remains fully operational.",
        "Array enters a degraded state but remains accessible.",
        "Array fails completely, and data is lost.",
        "Array automatically rebuilds using parity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 mirrors data; one failure keeps the array running but without redundancy. Both drives must fail for data loss. Rebuilding needs a new drive; RAID 1 doesn’t use parity.",
      "examTip": "RAID 1 loses one? Still runs."
    },
    {
      "id": 83,
      "question": "A server’s SFTP transfers are slow despite fast network links. What should you check first?\n\nA. Server’s CPU utilization during transfers.\nB. SFTP client’s buffer settings.\nC. Network switch’s flow control.\nD. Server’s disk I/O performance.",
      "options": [
        "Server’s CPU utilization during transfers.",
        "SFTP client’s buffer settings.",
        "Network switch’s flow control.",
        "Server’s disk I/O performance."
      ],
      "correctAnswerIndex": 0,
      "explanation": "SFTP’s encryption taxes CPU; high utilization slows transfers. Buffers, flow control, or disk I/O impact performance but CPU is the encryption bottleneck.",
      "examTip": "SFTP crawls? CPU’s encrypting."
    },
    {
      "id": 84,
      "question": "A server’s hot-aisle/cold-aisle configuration is ineffective. What’s the likely cause?\n\nA. Servers are not aligned with airflow direction.\nB. Rack doors are left open during operation.\nC. Cooling units are set to recirculation mode.\nD. Server density exceeds cooling capacity.",
      "options": [
        "Servers are not aligned with airflow direction.",
        "Rack doors are left open during operation.",
        "Cooling units are set to recirculation mode.",
        "Server density exceeds cooling capacity."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Misaligned servers disrupt hot/cold separation, mixing airflows. Open doors, recirculation, or density issues also impair efficiency but alignment is foundational.",
      "examTip": "Aisles mix? Servers misaimed."
    },
    {
      "id": 85,
      "question": "A server’s VM snapshot fails with ‘insufficient space.’ What should you do first?\n\nA. Increase the VM’s disk size.\nB. Delete unused snapshots.\nC. Check the datastore’s free space.\nD. Revert to a previous snapshot.",
      "options": [
        "Increase the VM’s disk size.",
        "Delete unused snapshots.",
        "Check the datastore’s free space.",
        "Revert to a previous snapshot."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Snapshots fill the datastore; checking free space confirms the issue. Increasing disk size, deleting snapshots, or reverting are next steps after verification.",
      "examTip": "Snapshot space? Datastore’s full."
    },
    {
      "id": 86,
      "question": "A server’s blade enclosure loses power to one blade. What’s the first check?\n\nA. Blade’s power supply module.\nB. Enclosure’s backplane connections.\nC. Blade’s firmware version.\nD. Enclosure’s management interface.",
      "options": [
        "Blade’s power supply module.",
        "Enclosure’s backplane connections.",
        "Blade’s firmware version.",
        "Enclosure’s management interface."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The backplane delivers power; a faulty connection can isolate one blade. PSU modules, firmware, or management issues typically affect more than one blade.",
      "examTip": "Blade powerless? Backplane’s link."
    },
    {
      "id": 87,
      "question": "A server’s RDP access fails with ‘protocol error.’ What’s the first check?\n\nA. RDP client version compatibility.\nB. Server’s RDP service status.\nC. Network latency between client and server.\nD. Server’s firewall rules.",
      "options": [
        "RDP client version compatibility.",
        "Server’s RDP service status.",
        "Network latency between client and server.",
        "Server’s firewall rules."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A ‘protocol error’ suggests the RDP service is down or misconfigured. Client versions, latency, or firewalls typically cause connection or timeout errors instead.",
      "examTip": "RDP protocol fails? Service check."
    },
    {
      "id": 88,
      "question": "A server’s iDRAC interface is unresponsive, but the server operates normally. What’s the first check?\n\nA. iDRAC firmware version.\nB. Server’s network connectivity.\nC. iDRAC’s dedicated NIC status.\nD. Server’s BIOS settings.",
      "options": [
        "iDRAC firmware version.",
        "Server’s network connectivity.",
        "iDRAC’s dedicated NIC status.",
        "Server’s BIOS settings."
      ],
      "correctAnswerIndex": 2,
      "explanation": "iDRAC often uses a dedicated NIC; if it’s offline, iDRAC fails. Firmware, general network, or BIOS issues are less specific to iDRAC’s isolated unresponsiveness.",
      "examTip": "iDRAC out? NIC’s down."
    },
    {
      "id": 89,
      "question": "A server’s ECC memory logs correctable errors. What should you do first?\n\nA. Replace the faulty RAM module.\nB. Monitor error rates for trends.\nC. Update the server’s BIOS.\nD. Increase the server’s cooling.",
      "options": [
        "Replace the faulty RAM module.",
        "Monitor error rates for trends.",
        "Update the server’s BIOS.",
        "Increase the server’s cooling."
      ],
      "correctAnswerIndex": 1,
      "explanation": "ECC corrects minor errors; monitoring trends determines if they’re escalating, warranting replacement. Replacing RAM, updating BIOS, or cooling are premature without data.",
      "examTip": "ECC logs errors? Watch, don’t switch."
    },
    {
      "id": 90,
      "question": "A server’s firewall blocks incoming traffic on port 443. What service is impacted?\n\nA. SSH\nB. HTTPS\nC. FTP\nD. SMTP",
      "options": [
        "SSH",
        "HTTPS",
        "FTP",
        "SMTP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Port 443 supports HTTPS for secure web traffic. SSH uses 22, FTP uses 21, and SMTP uses 25.",
      "examTip": "443 blocked? HTTPS stops."
    },
    {
      "id": 91,
      "question": "A server’s RAID 6 array with eight drives loses two drives. What’s the operational status?\n\nA. Fully operational with full redundancy.\nB. Degraded but still redundant.\nC. Degraded with no redundancy.\nD. Failed with data loss.",
      "options": [
        "Fully operational with full redundancy.",
        "Degraded but still redundant.",
        "Degraded with no redundancy.",
        "Failed with data loss."
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 6 handles two failures, remaining operational but losing its dual parity redundancy. Further failures risk data loss.",
      "examTip": "RAID 6 drops two? No spare shield."
    },
    {
      "id": 92,
      "question": "A server’s SNMP trap fails to send alerts. What’s the first check?\n\nA. SNMP service status.\nB. Trap destination configuration.\nC. Server’s network connectivity.\nD. SNMP community string.",
      "options": [
        "SNMP service status.",
        "Trap destination configuration.",
        "Server’s network connectivity.",
        "SNMP community string."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Incorrect trap destination settings stop alerts from reaching the target. Service status, connectivity, or community strings affect SNMP broadly, not just traps.",
      "examTip": "Traps miss? Aim’s off."
    },
    {
      "id": 93,
      "question": "A server’s hypervisor fails to allocate resources to a new VM. What’s the first check?\n\nA. Hypervisor license limits.\nB. Physical resource availability.\nC. VM configuration settings.\nD. Hypervisor storage capacity.",
      "options": [
        "Hypervisor license limits.",
        "Physical resource availability.",
        "VM configuration settings.",
        "Hypervisor storage capacity."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Insufficient physical resources (CPU, RAM) block VM creation. Licensing, VM settings, or storage issues arise after resource availability is confirmed.",
      "examTip": "VM won’t spawn? Host’s drained."
    },
    {
      "id": 94,
      "question": "A server’s UPS triggers a low battery alarm during a power outage. What should you investigate?\n\nA. UPS load capacity versus server draw.\nB. Server’s power management settings.\nC. UPS battery age and health.\nD. PDU circuit breaker status.",
      "options": [
        "UPS load capacity versus server draw.",
        "Server’s power management settings.",
        "UPS battery age and health.",
        "PDU circuit breaker status."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A low battery alarm suggests aging or degraded batteries failing to hold charge. Load capacity, power settings, or breakers influence runtime but not battery condition directly.",
      "examTip": "UPS low fast? Battery’s faded."
    },
    {
      "id": 95,
      "question": "A server’s network monitoring shows high retransmission rates. What’s the likely cause?\n\nA. Network interface card failure.\nB. Switch port duplex mismatch.\nC. Server’s CPU overload.\nD. Firewall blocking traffic.",
      "options": [
        "Network interface card failure.",
        "Switch port duplex mismatch.",
        "Server’s CPU overload.",
        "Firewall blocking traffic."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Duplex mismatches cause collisions, triggering retransmissions. NIC failure, CPU overload, or firewalls lead to drops or latency, not retransmissions specifically.",
      "examTip": "Retransmits up? Duplex clashes."
    },
    {
      "id": 96,
      "question": "A server’s redundant cooling fans fail simultaneously. What’s the probable cause?\n\nA. Fan controller malfunction.\nB. BIOS fan speed settings.\nC. Server room overheating.\nD. PSU voltage irregularity.",
      "options": [
        "Fan controller malfunction.",
        "BIOS fan speed settings.",
        "Server room overheating.",
        "PSU voltage irregularity."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A defective fan controller can stop all fans at once. BIOS settings, room temp, or PSU issues affect operation but not simultaneous failure.",
      "examTip": "All fans quit? Controller’s shot."
    },
    {
      "id": 97,
      "question": "A server’s print spooler service crashes repeatedly. What should you do first?\n\nA. Reinstall the printer drivers.\nB. Check the print server logs.\nC. Increase the spooler’s memory allocation.\nD. Update the server’s OS patches.",
      "options": [
        "Reinstall the printer drivers.",
        "Check the print server logs.",
        "Increase the spooler’s memory allocation.",
        "Update the server’s OS patches."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Logs identify crash causes (e.g., corrupt jobs, driver issues). Reinstalling drivers, boosting memory, or patching follow after diagnosis.",
      "examTip": "Spooler down? Logs reveal."
    },
    {
      "id": 98,
      "question": "A server’s RAID 10 array with six drives loses two drives in the same stripe set. What’s the status?\n\nA. Array remains fully operational.\nB. Array enters degraded mode.\nC. Array fails completely.\nD. Array automatically rebuilds.",
      "options": [
        "Array remains fully operational.",
        "Array enters degraded mode.",
        "Array fails completely.",
        "Array automatically rebuilds."
      ],
      "correctAnswerIndex": 2,
      "explanation": "In RAID 10, losing two drives in one stripe set destroys that stripe, failing the array. Losses across different sets allow degraded operation.",
      "examTip": "RAID 10 same stripe out? Done."
    },
    {
      "id": 99,
      "question": "A server’s application fails to start after a reboot, with ‘missing DLL’ errors. What’s the first step?\n\nA. Reinstall the application.\nB. Check the system’s PATH variable.\nC. Update the application’s dependencies.\nD. Restore from a backup.",
      "options": [
        "Reinstall the application.",
        "Check the system’s PATH variable.",
        "Update the application’s dependencies.",
        "Restore from a backup."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A ‘missing DLL’ error suggests the DLL isn’t in PATH or the app’s directory. Reinstalling, updating, or restoring are bigger steps without pinpointing the issue.",
      "examTip": "DLL lost? PATH’s the guide."
    },
    {
      "id": 100,
      "question": "A server’s hypervisor fails to migrate VMs due to ‘resource contention.’ What should you address?\n\nA. Increase the destination host’s CPU capacity.\nB. Reduce the VM’s resource allocation.\nC. Check the network bandwidth availability.\nD. Verify storage I/O performance.",
      "options": [
        "Increase the destination host’s CPU capacity.",
        "Reduce the VM’s resource allocation.",
        "Check the network bandwidth availability.",
        "Verify storage I/O performance."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Resource contention often means the destination host lacks CPU or RAM for migration. Reducing VM resources, network, or storage checks address different issues.",
      "examTip": "Migration halts? Host needs juice."
    }
  ]
});
