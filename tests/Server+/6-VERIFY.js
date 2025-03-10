make explanantions more in depth


remve 25 questions and make 25 differtn ones


db.tests.insertOne({
  "category": "serverplus",
  "testId": 6,
  "testName": "Server+ Practice Test #6 (Formidable)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A server’s RAID 5 array with five drives experiences two simultaneous drive failures. What is the operational status?",
      "options": [
        "Fully operational with reduced performance",
        "Degraded but accessible",
        "Completely failed with data loss",
        "Automatically rebuilding using parity"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 5 tolerates only one drive failure using parity. Two simultaneous failures exceed this, causing complete array failure and data loss. Degraded states or rebuilding apply to single failures.",
      "examTip": "RAID 5’s limit is one—two kills it."
    },
    {
      "id": 2,
      "question": "A virtualization host with 64 GB RAM and four VMs, each allocated 16 GB, faces memory overcommitment issues. What should you adjust first?",
      "options": [
        "Increase host RAM to 128 GB",
        "Reduce each VM’s memory to 12 GB",
        "Enable memory ballooning on VMs",
        "Set memory reservations for critical VMs"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Reservations guarantee RAM for critical VMs, reducing contention. Increasing RAM is costlier, reducing allocation may underperform, and ballooning doesn’t prioritize key VMs.",
      "examTip": "Overcommit? Reserve smartly."
    },
    {
      "id": 3,
      "question": "A server’s gigabit Ethernet interface shows high collision rates. What’s the most likely cause?",
      "options": [
        "Duplex mismatch with the switch",
        "Faulty network cable",
        "Overloaded switch",
        "Misconfigured VLAN on the NIC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Collisions on gigabit Ethernet suggest a duplex mismatch, forcing half-duplex mode. Cables cause drops, switches cause latency, and VLANs affect connectivity differently.",
      "examTip": "Collisions on gigabit? Duplex clash."
    },
    {
      "id": 4,
      "question": "A disaster recovery plan demands a 15-minute RTO for a critical server. Which solution fits best?",
      "options": [
        "Hot site with synchronous replication",
        "Warm site with asynchronous replication",
        "Cloud VM with real-time backups",
        "Cold site with daily snapshots"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hot sites with synchronous replication enable near-instant failover, meeting the tight RTO. Other options take longer to restore or sync.",
      "examTip": "Short RTO? Hot and synced."
    },
    {
      "id": 5,
      "question": "A server’s PSU fails, yet it stays online. What enabled this?",
      "options": [
        "Redundant power supplies with load balancing",
        "UPS with automatic voltage regulation",
        "Hot-swap capable PSU",
        "Low-power mode configuration"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Redundant PSUs ensure uptime if one fails. UPS backs up power, hot-swap aids replacement, and low-power mode doesn’t prevent failure effects.",
      "examTip": "PSU out, still on? Redundancy wins."
    },
    {
      "id": 6,
      "question": "SSH access is restricted to specific IPs, but an allowed IP is denied. What should you check first?",
      "options": [
        "Server firewall rules for port 22",
        "SSH service IP restrictions",
        "Switch ACL blocking the IP",
        "Server routing table"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A switch ACL could override server settings, blocking the IP. Firewall, SSH config, or routing issues are less likely if the IP is explicitly allowed.",
      "examTip": "SSH denied, IP ok? Switch blocks."
    },
    {
      "id": 7,
      "question": "A RAID 6 array with six drives loses three drives. What’s the status?",
      "options": [
        "Operational with reduced performance",
        "Critical but accessible",
        "Completely failed with data loss",
        "Rebuilding with dual parity"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 6 handles two failures via dual parity; three exceeds this, causing total failure. Lesser states apply to one or two failures.",
      "examTip": "RAID 6 caps at two—three’s fatal."
    },
    {
      "id": 8,
      "question": "Performance monitoring shows high disk I/O wait times but low CPU and RAM usage. What should you upgrade first?",
      "options": [
        "Faster SSDs with higher IOPS",
        "More RAM to reduce paging",
        "Higher clock speed CPU",
        "10GbE network bandwidth"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High I/O wait signals a disk bottleneck; faster SSDs address this directly. RAM, CPU, or network upgrades target unrelated issues here.",
      "examTip": "I/O waits high? Disks need speed."
    },
    {
      "id": 9,
      "question": "A server room’s access system fails, granting unrestricted entry. What’s the immediate mitigation?",
      "options": [
        "Station security personnel at the entrance",
        "Lock individual server racks",
        "Disconnect servers from the network",
        "Shut down non-critical servers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Guards enforce access control instantly. Locking racks, disconnecting, or shutting down are less immediate or more disruptive.",
      "examTip": "Access fails? Guards step in."
    },
    {
      "id": 10,
      "question": "Network latency spikes during backups despite ample bandwidth. What should you check first?",
      "options": [
        "Backup app compression settings",
        "Server NIC teaming config",
        "Switch QoS policies",
        "Backup server CPU usage"
      ],
      "correctAnswerIndex": 2,
      "explanation": "QoS might throttle backup traffic, raising latency. Compression, teaming, or CPU issues impact performance differently, not latency as directly.",
      "examTip": "Backup lags? QoS might pinch."
    },
    {
      "id": 11,
      "question": "A Linux server’s ZFS pool slows after enabling deduplication. Why?",
      "options": [
        "Higher CPU overhead",
        "Insufficient RAM for dedup tables",
        "Disk I/O contention",
        "Network latency"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Deduplication needs significant RAM for DDTs; too little RAM forces disk swaps, slowing performance. CPU, I/O, or network are secondary without RAM limits.",
      "examTip": "ZFS dedup lags? RAM’s short."
    },
    {
      "id": 12,
      "question": "A server’s CMOS battery dies, resetting the time. What else might reset?",
      "options": [
        "RAID controller config",
        "BIOS boot order",
        "SSL certificates",
        "App license keys"
      ],
      "correctAnswerIndex": 1,
      "explanation": "CMOS holds BIOS settings like boot order; a failure resets them. RAID, certs, and licenses are stored elsewhere.",
      "examTip": "CMOS out? BIOS reverts."
    },
    {
      "id": 13,
      "question": "An active-active cluster hits split-brain syndrome. What’s the likely cause?",
      "options": [
        "Quorum disk failure",
        "Network partition between nodes",
        "Misconfigured failover policies",
        "Low CPU resources"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Split-brain happens when nodes lose contact, each acting independently. Quorum, failover, or CPU issues cause other cluster failures.",
      "examTip": "Cluster splits? Network’s split."
    },
    {
      "id": 14,
      "question": "An iSCSI connection drops during high I/O, with stable network and SAN. What should you tweak first?",
      "options": [
        "Increase iSCSI timeout values",
        "Update HBA firmware",
        "Check SAN LUN queue depth",
        "Verify network MTU"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High I/O can exceed default timeouts, causing drops; raising them helps. Firmware, queue depth, or MTU issues are less tied to I/O spikes.",
      "examTip": "iSCSI drops on load? Timeouts stretch."
    },
    {
      "id": 15,
      "question": "A DR plan needs a 30-minute RPO for a database. What’s the best backup method?",
      "options": [
        "Hourly incremental backups",
        "Real-time transaction log shipping",
        "Daily full with differentials",
        "15-minute snapshots"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Log shipping captures changes nearly instantly, meeting the 30-minute RPO. Hourly, daily, or even 15-minute options may exceed or just scrape by.",
      "examTip": "Tight RPO? Logs flow fast."
    },
    {
      "id": 16,
      "question": "A server logs frequent ‘page fault’ errors. What should you check first?",
      "options": [
        "Low RAM causing paging",
        "Corrupted app binaries",
        "Faulty swap space sectors",
        "Virtual memory misconfig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Page faults often signal insufficient RAM, pushing to disk. Binaries, sectors, or configs cause crashes or different errors.",
      "examTip": "Page faults up? RAM’s down."
    },
    {
      "id": 17,
      "question": "A Fibre Channel SAN link fails post-SAN firmware update. What’s the first check?",
      "options": [
        "SAN switch zoning",
        "HBA driver compatibility",
        "Fibre cable integrity",
        "SAN LUN masking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firmware updates can mismatch HBA drivers, breaking links. Zoning, cables, or masking issues are less likely without other changes.",
      "examTip": "FC down after update? Drivers differ."
    },
    {
      "id": 18,
      "question": "NIC teaming with LACP doesn’t balance traffic evenly. What should you adjust?",
      "options": [
        "Switch to active-passive mode",
        "Change LACP hashing algorithm",
        "Modify NIC duplex settings",
        "Reconfigure switch port channels"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tweaking the hash (e.g., IP-based) improves distribution. Mode changes, duplex, or port configs alter function, not balance.",
      "examTip": "LACP lopsided? Hash tweak."
    },
    {
      "id": 19,
      "question": "A PowerShell script fails with ‘access denied’ on a remote Windows server. What’s the first check?",
      "options": [
        "Remote firewall rules",
        "Script execution policy",
        "User permissions on remote server",
        "PowerShell remoting setup"
      ],
      "correctAnswerIndex": 2,
      "explanation": "‘Access denied’ usually means insufficient remote permissions. Firewall, policy, or remoting issues give different errors.",
      "examTip": "PS remote blocked? Perms short."
    },
    {
      "id": 20,
      "question": "A RAID 5 array with SSDs has slower-than-expected reads. What’s the likely cause?",
      "options": [
        "SSDs not optimized for sequential reads",
        "RAID controller missing read-ahead cache",
        "Large stripe size config",
        "SATA instead of NVMe connection"
      ],
      "correctAnswerIndex": 1,
      "explanation": "No read-ahead cache hampers prefetching, slowing reads. Optimization, stripe size, or SATA affect differently.",
      "examTip": "RAID 5 reads slow? Cache missing."
    },
    {
      "id": 21,
      "question": "A firewall allows only HTTPS, but web apps are down. What’s the first check?",
      "options": [
        "SSL certificate validity",
        "Firewall rules for port 443",
        "Network interface status",
        "Web server service status"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A stopped web service blocks apps despite open ports. Certs, rules, or NIC issues cause other symptoms.",
      "examTip": "HTTPS on, apps off? Service check."
    },
    {
      "id": 22,
      "question": "A server crashes post-RAM upgrade with memory errors. What’s the first step?",
      "options": [
        "Update BIOS",
        "Test new RAM individually",
        "Increase virtual memory",
        "Replace motherboard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Testing isolates bad RAM. BIOS, virtual memory, or mobo swaps are broader fixes without pinpointing.",
      "examTip": "New RAM crashes? Test sticks."
    },
    {
      "id": 23,
      "question": "VMs with NAT networking talk internally but not externally. What’s the first check?",
      "options": [
        "Guest OS firewall",
        "Hypervisor NAT config",
        "Switch VLAN settings",
        "Server routing table"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hypervisor NAT controls external access; misconfigs block it. Firewalls, VLANs, or routing hit differently.",
      "examTip": "NAT VMs blind? Hypervisor gates."
    },
    {
      "id": 24,
      "question": "Backups fail from insufficient space despite dedup. What should you adjust first?",
      "options": [
        "Increase target storage",
        "Reduce retention period",
        "Disable deduplication",
        "Compress backup streams"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Shorter retention frees space by dropping old backups. More storage costs, disabling dedup wastes, compression may not cut it.",
      "examTip": "Backups full? Cut history."
    },
    {
      "id": 25,
      "question": "Ping works, but SSH fails with ‘connection timed out’ to a remote host. What’s the likely cause?",
      "options": [
        "Remote firewall blocks port 22",
        "Server SSH client misconfig",
        "High network latency",
        "Remote SSH service down"
      ],
      "correctAnswerIndex": 3,
      "explanation": "‘Timed out’ means no response; the SSH service is likely off. Firewall gives ‘refused,’ client issues give auth errors, latency slows but connects.",
      "examTip": "Ping yes, SSH no? Service off."
    },
    {
      "id": 26,
      "question": "Disk performance lags despite IOPS within limits. What should you investigate?",
      "options": [
        "Disk latency and queue depth",
        "CPU usage during disk ops",
        "Network bandwidth saturation",
        "RAM paging rates"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High latency or queues signal contention beyond IOPS. CPU, network, or RAM affect other areas.",
      "examTip": "IOPS fine, still slow? Latency hides."
    },
    {
      "id": 27,
      "question": "A biometric access system fails, defaulting to open. What’s the best temp fix?",
      "options": [
        "Station guards at the scanner",
        "Manually lock the room",
        "Disconnect critical servers",
        "Use temp keycards"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Guards enforce control fast. Locking, disconnecting, or keycards are slower or disruptive.",
      "examTip": "Biometrics off? Guards on."
    },
    {
      "id": 28,
      "question": "A RAID 10 array with eight drives loses three drives across different mirrors. What’s the status?",
      "options": [
        "Fully operational",
        "Degraded but accessible",
        "Completely failed",
        "Read-only mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 10 survives one failure per mirror; three across sets keeps it degraded. Same-set losses kill it; read-only isn’t standard.",
      "examTip": "RAID 10 spread out? Degraded lives."
    },
    {
      "id": 29,
      "question": "A valid HTTPS cert triggers ‘untrusted’ warnings on clients. What’s the first check?",
      "options": [
        "Server time and date",
        "Cert issuing authority chain",
        "Server IP config",
        "Client browser settings"
      ],
      "correctAnswerIndex": 1,
      "explanation": "‘Untrusted’ often means a broken trust chain (e.g., missing intermediates). Time causes expiry errors, IP affects reach, browser is client-side.",
      "examTip": "Cert untrusted? Chain check."
    },
    {
      "id": 30,
      "question": "Fans run at max speed despite normal temps. What’s the first check?",
      "options": [
        "BIOS fan controls",
        "Temp sensor calibration",
        "PSU voltage stability",
        "Dust buildup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Bad sensors can misreport temps, maxing fans. BIOS, PSU, or dust affect cooling but not fan speed directly if temps are fine.",
      "examTip": "Fans scream, temps ok? Sensors off."
    },
    {
      "id": 31,
      "question": "A per-core licensed app lags with many cores. What’s the best fix?",
      "options": [
        "Switch to per-socket licensing",
        "Optimize for multi-threading",
        "Reduce licensed cores",
        "Upgrade to faster single-core CPUs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multi-threading optimization uses all cores well. Licensing changes, core cuts, or CPU swaps don’t fix app inefficiency.",
      "examTip": "App slow on cores? Thread it."
    },
    {
      "id": 32,
      "question": "OS install fails with ‘hardware not supported,’ despite HCL listing. What’s the first check?",
      "options": [
        "Install media integrity",
        "BIOS version compatibility",
        "Hardware firmware updates",
        "Install config options"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Old firmware can break compatibility despite HCL. Media, BIOS, or configs are less likely if firmware lags.",
      "examTip": "HCL ok, install no? Firmware check."
    },
    {
      "id": 33,
      "question": "Synchronous replication fails from network latency. What’s the best alternative?",
      "options": [
        "Increase network bandwidth",
        "Switch to asynchronous replication",
        "Use WAN optimization",
        "Relax RPO"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Asynchronous replication handles latency by allowing lag. Bandwidth, optimization, or RPO tweaks don’t fix sync directly.",
      "examTip": "Sync fails? Async fits."
    },
    {
      "id": 34,
      "question": "A virtual switch stops traffic after a hypervisor patch. What’s the first check?",
      "options": [
        "Virtual switch VLANs",
        "Hypervisor network driver",
        "VM guest OS settings",
        "Physical switch STP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A patch can break driver compatibility, halting the switch. VLANs, guest OS, or STP are less likely post-patch alone.",
      "examTip": "Patch kills vSwitch? Driver clash."
    },
    {
      "id": 35,
      "question": "Drives need secure erasure before disposal without physical destruction. What’s the best method?",
      "options": [
        "Quick format with zero-fill",
        "Multi-pass random overwrite",
        "Degaussing platters",
        "Encrypt and delete keys"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multi-pass overwrite ensures no recovery. Formatting, degaussing, or encryption are less thorough without destruction.",
      "examTip": "Secure wipe? Multi-pass rules."
    },
    {
      "id": 36,
      "question": "Full-disk encryption slows an app significantly. What’s the best fix?",
      "options": [
        "Upgrade CPU",
        "Offload encryption to hardware",
        "Increase app memory",
        "Disable background services"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hardware offload (e.g., TPM) cuts CPU load. CPU, memory, or services target general performance, not encryption.",
      "examTip": "Encryption slows? Hardware lifts."
    },
    {
      "id": 37,
      "question": "Cat7 cables support 10GbE, but the network runs at 1GbE. What’s the first check?",
      "options": [
        "NIC speed and duplex",
        "Switch port speed",
        "Cable length and quality",
        "BIOS network settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIC settings might cap at 1GbE. Switch, cables, or BIOS follow if NIC is off.",
      "examTip": "1GbE on Cat7? NIC limits."
    },
    {
      "id": 38,
      "question": "A RAID controller battery fails, forcing write-through mode. What’s the immediate impact?",
      "options": [
        "Slower write performance",
        "Improved read performance",
        "Degraded array state",
        "Higher data integrity risk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Write-through skips cache, slowing writes. Reads, array state, or integrity aren’t hit directly.",
      "examTip": "Battery gone? Writes drag."
    },
    {
      "id": 39,
      "question": "RBAC gives users excessive permissions. What’s the first audit step?",
      "options": [
        "Review user accounts",
        "Examine role definitions",
        "Check group policy inheritance",
        "Analyze file system ACLs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Role definitions show where perms are overgranted. Accounts, policies, or ACLs follow if roles are off.",
      "examTip": "RBAC loose? Roles first."
    },
    {
      "id": 40,
      "question": "SAN performance drops during peak use with multipathing. What’s the first check?",
      "options": [
        "SAN queue depth",
        "HBA load balancing",
        "Network latency on paths",
        "SAN controller cache"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Poor HBA balancing overloads paths at peak. Queue, latency, or cache are next if balancing fails.",
      "examTip": "SAN peaks slow? HBA balance."
    },
    {
      "id": 41,
      "question": "What’s the main advantage of synthetic full backups over traditional fulls?",
      "options": [
        "Less storage space",
        "Faster backup times",
        "Easier restores",
        "Lower bandwidth use"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Synthetics merge incrementals into one file, simplifying restores. Storage, speed, or bandwidth gains are less direct.",
      "examTip": "Synthetic fulls? Restore’s quick."
    },
    {
      "id": 42,
      "question": "A RAID 1 array loses one drive. What’s the first action before replacing it?",
      "options": [
        "Start array rebuild",
        "Back up remaining drive",
        "Update RAID firmware",
        "Check failed drive SMART"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Backing up guards against a second failure. Rebuilding, updating, or SMART checks risk data without backup.",
      "examTip": "RAID 1 one down? Backup first."
    },
    {
      "id": 43,
      "question": "Tracert shows high latency at hop 5 to a remote host. What does this suggest?",
      "options": [
        "Server NIC malfunction",
        "Remote host overload",
        "Congestion at hop 5",
        "DNS delay"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Latency at one hop points to congestion there. NIC, host, or DNS affect the whole path or resolution.",
      "examTip": "Tracert lags mid? Hop’s jammed."
    },
    {
      "id": 44,
      "question": "A VM fails to start post-snapshot revert with ‘disk corruption.’ What’s the first step?",
      "options": [
        "Check virtual disk integrity",
        "Increase VM disk space",
        "Revert to older snapshot",
        "Update hypervisor"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corruption requires disk file checks. Space, older snapshots, or updates don’t fix corruption directly.",
      "examTip": "VM disk corrupt? File’s bad."
    },
    {
      "id": 45,
      "question": "A server room sees voltage swings during peak hours. What’s the best fix?",
      "options": [
        "UPS with voltage regulation",
        "Higher wattage PSU",
        "Power capping on servers",
        "Redundant power feeds"
      ],
      "correctAnswerIndex": 0,
      "explanation": "UPS with AVR stabilizes voltage. PSU upgrades, capping, or feeds don’t regulate incoming power.",
      "examTip": "Voltage wobbles? AVR fixes."
    },
    {
      "id": 46,
      "question": "A RAID 10 array with six drives loses two in the same stripe set. What’s the status?",
      "options": [
        "Fully operational",
        "Degraded but accessible",
        "Completely failed",
        "Read-only mode"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 10 fails if both drives in one stripe die. Spread-out losses degrade; read-only isn’t typical.",
      "examTip": "RAID 10 same stripe gone? Dead."
    },
    {
      "id": 47,
      "question": "SNMPv3 auth fails despite correct credentials. What’s the first check?",
      "options": [
        "SNMP service user settings",
        "Encryption key config",
        "Trap destination addresses",
        "Network to manager"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wrong user settings (e.g., auth type) cause failures. Keys, traps, or network give other errors.",
      "examTip": "SNMPv3 auth out? User off."
    },
    {
      "id": 48,
      "question": "Performance drops during backups due to SAN saturation. What’s the best fix?",
      "options": [
        "Increase SAN bandwidth",
        "Throttle backups",
        "Upgrade server CPU",
        "Add backup server RAM"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Throttling eases SAN load. Bandwidth, CPU, or RAM help capacity, not saturation directly.",
      "examTip": "SAN choked? Throttle back."
    },
    {
      "id": 49,
      "question": "A server asset inventory lacks serial numbers. How should you update it?",
      "options": [
        "Manually inspect hardware",
        "Use management tools",
        "Check purchase orders",
        "Reference topology diagrams"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tools like IPMI pull serials remotely. Inspection’s slow, orders may lack detail, diagrams don’t list serials.",
      "examTip": "Serials lost? Tools find."
    },
    {
      "id": 50,
      "question": "NTP sync fails with ‘authentication error.’ What’s the first check?",
      "options": [
        "NTP server public key",
        "Client auth settings",
        "Firewall NTP rules",
        "Server time zone"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Auth errors stem from client key mismatches. Server keys, firewalls, or zones cause other issues.",
      "examTip": "NTP auth fails? Client key."
    },
    {
      "id": 51,
      "question": "A server’s RAID 10 array with six drives experiences two drive failures in different mirror sets. What is the array’s status?",
      "options": [
        "Fully operational with full redundancy",
        "Degraded but still redundant",
        "Degraded with no redundancy",
        "Failed with data loss"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 10 combines mirroring and striping. Losing one drive per mirror set keeps the array operational but degraded, with no redundancy left. If both drives in one mirror set fail, the array fails entirely. Here, different mirror sets mean it’s degraded without redundancy."
    },
    {
      "id": 52,
      "question": "A virtualization host with 128 GB RAM and eight VMs, each allocated 16 GB, shows high memory contention. What should you adjust first?",
      "options": [
        "Increase host RAM to 256 GB",
        "Reduce each VM’s memory to 12 GB",
        "Enable memory overcommitment",
        "Set memory reservations for critical VMs"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Memory reservations guarantee RAM for critical VMs, reducing contention effectively. Adding RAM is expensive, reducing allocations may underperform, and overcommitment risks stability without prioritization."
    },
    {
      "id": 53,
      "question": "A server’s 10GbE interface reports high CRC errors. What’s the most likely cause?",
      "options": [
        "Faulty network cable",
        "Duplex mismatch with the switch",
        "Overloaded switch buffer",
        "Misconfigured VLAN on the NIC"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CRC errors indicate frame corruption, commonly from a faulty cable. Duplex mismatches cause collisions, buffer overloads lead to drops, and VLAN issues affect connectivity, not CRC."
    },
    {
      "id": 54,
      "question": "A disaster recovery plan requires a 2-hour RTO for a critical server. Which solution is most cost-effective?",
      "options": [
        "Hot site with real-time replication",
        "Warm site with hourly backups",
        "Cloud VM with asynchronous replication",
        "Cold site with daily backups"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A cloud VM with async replication meets the 2-hour RTO at a lower cost than a hot site. Warm sites may exceed 2 hours, and cold sites require too much setup time."
    },
    {
      "id": 55,
      "question": "A server’s PSU fan runs at maximum speed constantly. What should you check first?",
      "options": [
        "PSU temperature sensor",
        "BIOS fan control settings",
        "Server room ambient temperature",
        "PSU firmware version"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A faulty PSU temperature sensor can misreport, causing constant high fan speed. BIOS settings, room temp, or firmware are secondary unless the sensor is confirmed functional."
    },
    {
      "id": 56,
      "question": "SSH access fails with ‘host key verification failed’ after a server rebuild. What’s the first step?",
      "options": [
        "Update the SSH client’s known_hosts file",
        "Regenerate the server’s SSH host keys",
        "Check the server’s firewall rules",
        "Verify the server’s IP address"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A rebuild changes the server’s host key; updating the client’s known_hosts resolves the mismatch. Regenerating keys again or checking firewall/IP are unnecessary here."
    },
    {
      "id": 57,
      "question": "A RAID 5 array with four drives loses two drives. What’s the status?",
      "options": [
        "Operational with reduced performance",
        "Degraded but accessible",
        "Completely failed with data loss",
        "Rebuilding using parity"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 5 tolerates only one drive failure. Two failures result in complete array failure and data loss. Degraded applies to one failure; rebuilding requires a spare."
    },
    {
      "id": 58,
      "question": "Monitoring shows high CPU ready times but low utilization on a VM host. What should you adjust first?",
      "options": [
        "Increase host CPU cores",
        "Decrease vCPUs per VM",
        "Enable CPU affinity",
        "Upgrade to faster RAM"
      ],
      "correctAnswerIndex": 1,
      "explanation": "High ready times indicate CPU scheduling contention; reducing vCPUs per VM eases this. More cores cost more, affinity limits flexibility, and RAM doesn’t address CPU waits."
    },
    {
      "id": 59,
      "question": "A server room’s biometric system fails, defaulting to unlocked. What’s the immediate action?",
      "options": [
        "Station security at the door",
        "Lock server racks individually",
        "Disconnect critical servers",
        "Shut down non-essential systems"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Security personnel provide immediate access control. Locking racks, disconnecting servers, or shutting systems are slower or more disruptive."
    },
    {
      "id": 60,
      "question": "Network latency spikes during backups despite ample bandwidth. What should you check first?",
      "options": [
        "Backup application’s compression settings",
        "Server’s NIC teaming configuration",
        "Switch’s QoS policies",
        "Backup server’s disk I/O"
      ],
      "correctAnswerIndex": 2,
      "explanation": "QoS policies might throttle backup traffic, increasing latency. Compression, teaming, or disk I/O impact performance differently, not latency directly."
    },
    {
      "id": 61,
      "question": "A Linux server’s ext4 file system corrupts after a power loss. What should have been enabled?",
      "options": [
        "Journaling",
        "RAID parity",
        "UPS with AVR",
        "Disk quotas"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Journaling logs changes, aiding recovery after crashes. RAID, UPS, or quotas don’t directly prevent file system corruption."
    },
    {
      "id": 62,
      "question": "A server’s CMOS battery fails, but it boots normally. What’s the likely impact?",
      "options": [
        "Time and date reset on reboot",
        "RAID configuration loss",
        "SSL certificate expiration",
        "Application license invalidation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CMOS stores time and BIOS settings; failure resets time on reboot. RAID, certs, and licenses are unaffected."
    },
    {
      "id": 63,
      "question": "An active-passive cluster fails to failover during a test. What’s the likely cause?",
      "options": [
        "Quorum disk offline",
        "Network partition between nodes",
        "Misconfigured failover policies",
        "Low CPU resources on passive node"
      ],
      "correctAnswerIndex": 0,
      "explanation": "An offline quorum disk prevents failover decisions. Partitions, policies, or CPU issues cause different failures."
    },
    {
      "id": 64,
      "question": "An iSCSI connection times out during high I/O with a stable network and SAN. What should you adjust first?",
      "options": [
        "Increase iSCSI timeout values",
        "Update HBA firmware",
        "Check SAN LUN queue depth",
        "Verify network MTU"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High I/O can exceed default timeouts; increasing them compensates. Firmware, queue depth, or MTU are less immediate fixes."
    },
    {
      "id": 65,
      "question": "A DR plan requires a 1-hour RPO for a database. What’s the best backup method?",
      "options": [
        "Hourly incremental backups",
        "Real-time transaction log shipping",
        "Daily full with differentials",
        "30-minute snapshots"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Log shipping captures changes instantly, ensuring a 1-hour RPO. Hourly backups may miss it, daily is too slow, and snapshots may not suffice."
    },
    {
      "id": 66,
      "question": "A server logs ‘out of memory’ errors despite ample RAM. What should you check first?",
      "options": [
        "Application memory allocation limits",
        "Server virtual memory settings",
        "Hypervisor memory overprovisioning",
        "BIOS memory mapping config"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Application-specific memory caps can trigger errors despite free RAM. Virtual memory, hypervisor, or BIOS affect system-level issues."
    },
    {
      "id": 67,
      "question": "A Fibre Channel SAN link fails after a switch firmware update. What’s the first check?",
      "options": [
        "SAN switch zoning",
        "HBA driver compatibility",
        "Fibre cable integrity",
        "SAN LUN masking"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Firmware updates can disrupt HBA driver compatibility, breaking links. Zoning, cables, or masking are less likely without configuration changes."
    },
    {
      "id": 68,
      "question": "NIC teaming with LACP doesn’t distribute traffic evenly. What should you adjust?",
      "options": [
        "Switch to active-passive mode",
        "Change LACP hashing algorithm",
        "Modify NIC duplex settings",
        "Reconfigure switch port channels"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Adjusting the hashing algorithm (e.g., to IP-based) improves distribution. Mode changes, duplex, or port configs alter functionality, not balance."
    },
    {
      "id": 69,
      "question": "A PowerShell script fails with ‘command not found’ on a remote server. What’s the first check?",
      "options": [
        "Script syntax",
        "PowerShell execution policy",
        "Server PATH variable",
        "Script file permissions"
      ],
      "correctAnswerIndex": 2,
      "explanation": "‘Command not found’ suggests the command isn’t in the PATH. Syntax, policy, or permissions produce different errors."
    },
    {
      "id": 70,
      "question": "A RAID 5 array with SSDs has slower-than-expected writes. What’s the likely cause?",
      "options": [
        "SSDs not optimized for writes",
        "RAID controller lacks write-back cache",
        "Large stripe size",
        "SATA instead of NVMe"
      ],
      "correctAnswerIndex": 1,
      "explanation": "No write-back cache forces direct writes, slowing performance. SSD optimization, stripe size, or SATA have less impact."
    },
    {
      "id": 71,
      "question": "A firewall allows only HTTPS, but web apps are inaccessible. What’s the first check?",
      "options": [
        "SSL certificate validity",
        "Firewall rules for port 443",
        "Network interface status",
        "Web server service status"
      ],
      "correctAnswerIndex": 3,
      "explanation": "A stopped web service prevents access despite open ports. Certs, rules, or NICs cause different issues."
    },
    {
      "id": 72,
      "question": "A server crashes post-RAM upgrade with memory errors. What’s the first step?",
      "options": [
        "Update BIOS",
        "Test new RAM individually",
        "Increase virtual memory",
        "Replace motherboard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Testing isolates faulty RAM. BIOS updates, virtual memory, or mobo replacement are broader fixes."
    },
    {
      "id": 73,
      "question": "VMs with bridged networking can’t reach external networks, but the host can. What’s the first check?",
      "options": [
        "Guest OS firewall",
        "Hypervisor virtual switch config",
        "Switch VLAN settings",
        "Server routing table"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Guest firewalls can block traffic despite host connectivity. Virtual switch, VLANs, or routing affect broader issues."
    },
    {
      "id": 74,
      "question": "Backups fail from insufficient space despite compression. What should you adjust first?",
      "options": [
        "Increase target storage",
        "Reduce retention period",
        "Disable compression",
        "Use deduplication"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reducing retention frees space by dropping old backups. More storage costs, disabling compression wastes space, and deduplication may already be in use."
    },
    {
      "id": 75,
      "question": "Ping succeeds, but SSH fails with ‘connection refused’ to a remote host. What’s the likely cause?",
      "options": [
        "Remote firewall blocks port 22",
        "Server SSH client misconfig",
        "High network latency",
        "Remote SSH service down"
      ],
      "correctAnswerIndex": 3,
      "explanation": "‘Connection refused’ means the SSH service isn’t running. Firewall blocks give ‘timed out,’ client issues give auth errors, and latency slows but connects."
    },
    {
      "id": 76,
      "question": "Disk performance is slow despite sufficient IOPS. What should you investigate?",
      "options": [
        "Disk latency and queue depth",
        "CPU usage during disk ops",
        "Network bandwidth",
        "RAM paging"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High latency or queue depth indicates contention beyond IOPS. CPU, network, or RAM affect other areas."
    },
    {
      "id": 77,
      "question": "A biometric access system fails, defaulting to open. What’s the best temporary fix?",
      "options": [
        "Station guards at the door",
        "Lock server racks",
        "Disconnect critical servers",
        "Use temp keycards"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Guards enforce control quickly. Locking racks, disconnecting, or keycards take longer or disrupt operations."
    },
    {
      "id": 78,
      "question": "A RAID 10 array with eight drives loses three drives across different mirrors. What’s the status?",
      "options": [
        "Fully operational",
        "Degraded but accessible",
        "Completely failed",
        "Read-only mode"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 10 survives one failure per mirror; three across different sets keeps it degraded but functional. Same-set losses cause failure."
    },
    {
      "id": 79,
      "question": "A valid HTTPS cert triggers ‘untrusted’ warnings on clients. What’s the first check?",
      "options": [
        "Server time and date",
        "Cert issuing authority chain",
        "Server IP config",
        "Client browser settings"
      ],
      "correctAnswerIndex": 1,
      "explanation": "‘Untrusted’ often means a missing intermediate CA certificate. Time causes expiry errors, IP affects reachability, and browsers are client-side."
    },
    {
      "id": 80,
      "question": "Fans run at max speed despite normal temps. What’s the first check?",
      "options": [
        "BIOS fan controls",
        "Temp sensor calibration",
        "PSU voltage stability",
        "Dust buildup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Faulty sensors can misreport temps, maxing fans. BIOS, PSU, or dust affect cooling differently."
    },
    {
      "id": 81,
      "question": "A per-core licensed app lags with many cores. What’s the best fix?",
      "options": [
        "Switch to per-socket licensing",
        "Optimize for multi-threading",
        "Reduce licensed cores",
        "Upgrade to faster single-core CPUs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multi-threading optimization leverages all cores. Licensing changes, core reduction, or CPU swaps don’t address app efficiency."
    },
    {
      "id": 82,
      "question": "OS install fails with ‘hardware not supported,’ despite HCL listing. What’s the first check?",
      "options": [
        "Install media integrity",
        "BIOS version compatibility",
        "Hardware firmware updates",
        "Install config options"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Outdated firmware can break compatibility despite HCL. Media, BIOS, or config issues are less likely."
    },
    {
      "id": 83,
      "question": "Synchronous replication fails due to network latency. What’s the best alternative?",
      "options": [
        "Increase network bandwidth",
        "Switch to asynchronous replication",
        "Use WAN optimization",
        "Relax RPO"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Async replication tolerates latency by allowing lag. Bandwidth, optimization, or RPO changes don’t fix sync issues directly."
    },
    {
      "id": 84,
      "question": "A virtual switch stops traffic after a hypervisor patch. What’s the first check?",
      "options": [
        "Virtual switch VLANs",
        "Hypervisor network driver",
        "VM guest OS settings",
        "Physical switch STP"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A patch can break network drivers, halting the switch. VLANs, guest OS, or STP are less likely post-patch."
    },
    {
      "id": 85,
      "question": "Drives need secure erasure before disposal without destruction. What’s the best method?",
      "options": [
        "Quick format with zero-fill",
        "Multi-pass random overwrite",
        "Degaussing platters",
        "Encrypt and delete keys"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Multi-pass overwrite ensures no recovery. Formatting, degaussing, or encryption are less thorough without physical measures."
    },
    {
      "id": 86,
      "question": "Full-disk encryption slows an app significantly. What’s the best fix?",
      "options": [
        "Upgrade CPU",
        "Offload encryption to hardware",
        "Increase app memory",
        "Disable background services"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Hardware offload (e.g., TPM) reduces CPU load. CPU upgrades, memory, or services target general performance."
    },
    {
      "id": 87,
      "question": "Cat7 cables support 10GbE, but the network runs at 1GbE. What’s the first check?",
      "options": [
        "NIC speed and duplex",
        "Switch port speed",
        "Cable length and quality",
        "BIOS network settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "NIC settings might limit speed to 1GbE. Switch ports, cables, or BIOS are subsequent checks."
    },
    {
      "id": 88,
      "question": "A RAID controller battery fails, forcing write-through mode. What’s the immediate impact?",
      "options": [
        "Slower write performance",
        "Improved read performance",
        "Degraded array state",
        "Higher data integrity risk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Write-through skips cache, slowing writes. Reads, array state, or integrity aren’t directly affected."
    },
    {
      "id": 89,
      "question": "RBAC gives users excessive permissions. What’s the first audit step?",
      "options": [
        "Review user accounts",
        "Examine role definitions",
        "Check group policy inheritance",
        "Analyze file system ACLs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Role definitions reveal overgranted perms. Accounts, policies, or ACLs are checked afterward."
    },
    {
      "id": 90,
      "question": "SAN performance drops during peak use with multipathing. What’s the first check?",
      "options": [
        "SAN queue depth",
        "HBA load balancing",
        "Network latency on paths",
        "SAN controller cache"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Poor HBA balancing overloads paths. Queue depth, latency, or cache are next steps."
    },
    {
      "id": 91,
      "question": "What’s the main advantage of synthetic full backups over traditional fulls?",
      "options": [
        "Less storage space",
        "Faster backup times",
        "Easier restores",
        "Lower bandwidth use"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Synthetics merge incrementals into one file, simplifying restores. Storage, speed, or bandwidth benefits are secondary."
    },
    {
      "id": 92,
      "question": "A RAID 1 array loses one drive. What’s the first action before replacing it?",
      "options": [
        "Start array rebuild",
        "Back up remaining drive",
        "Update RAID firmware",
        "Check failed drive SMART"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Backing up protects against a second failure. Rebuilding, updating, or SMART checks risk data loss."
    },
    {
      "id": 93,
      "question": "Tracert shows high latency at hop 5 to a remote host. What does this suggest?",
      "options": [
        "Server NIC malfunction",
        "Remote host overload",
        "Congestion at hop 5",
        "DNS delay"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Latency at one hop indicates congestion there. NIC, host, or DNS affect the whole path differently."
    },
    {
      "id": 94,
      "question": "A VM fails to start post-snapshot revert with ‘disk corruption.’ What’s the first step?",
      "options": [
        "Check virtual disk integrity",
        "Increase VM disk space",
        "Revert to older snapshot",
        "Update hypervisor"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Corruption requires disk file checks. Space, older snapshots, or updates don’t address corruption."
    },
    {
      "id": 95,
      "question": "A server room sees voltage swings during peak hours. What’s the best fix?",
      "options": [
        "UPS with voltage regulation",
        "Higher wattage PSU",
        "Power capping on servers",
        "Redundant power feeds"
      ],
      "correctAnswerIndex": 0,
      "explanation": "UPS with AVR stabilizes voltage. PSU upgrades, capping, or feeds don’t regulate incoming power."
    },
    {
      "id": 96,
      "question": "A RAID 10 array with six drives loses two in the same stripe set. What’s the status?",
      "options": [
        "Fully operational",
        "Degraded but accessible",
        "Completely failed",
        "Read-only mode"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 10 fails if both drives in one stripe die. Losses across sets degrade it; read-only isn’t standard."
    },
    {
      "id": 97,
      "question": "SNMPv3 auth fails despite correct credentials. What’s the first check?",
      "options": [
        "SNMP service user settings",
        "Encryption key config",
        "Trap destination addresses",
        "Network to manager"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Wrong user settings (e.g., auth type) cause failures. Keys, traps, or network give different errors."
    },
    {
      "id": 98,
      "question": "Performance drops during backups due to SAN saturation. What’s the best fix?",
      "options": [
        "Increase SAN bandwidth",
        "Throttle backups",
        "Upgrade server CPU",
        "Add backup server RAM"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Throttling reduces SAN load. Bandwidth, CPU, or RAM address capacity, not saturation."
    },
    {
      "id": 99,
      "question": "A server asset inventory lacks serial numbers. How should you update it?",
      "options": [
        "Manually inspect hardware",
        "Use management tools",
        "Check purchase orders",
        "Reference topology diagrams"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Tools like IPMI retrieve serials efficiently. Inspection is slow, orders may lack detail, and diagrams don’t include serials."
    },
    {
      "id": 100,
      "question": "NTP sync fails with ‘authentication error.’ What’s the first check?",
      "options": [
        "NTP server public key",
        "Client auth settings",
        "Firewall NTP rules",
        "Server time zone"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Auth errors stem from client key mismatches. Server keys, firewalls, or zones cause other issues."
    }
  ]
});
