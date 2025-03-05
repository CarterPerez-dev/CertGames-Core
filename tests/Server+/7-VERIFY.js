db.tests.insertOne({
  "category": "serverplus",
  "testId": 7,
  "testName": "Server+ Practice Test #7 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A server’s RAID 10 array with eight drives experiences three drive failures: two in one mirror set and one in another. What is the operational status?",
      "options": [
        "Fully operational with reduced redundancy",
        "Degraded but still accessible with no redundancy",
        "Completely failed with total data loss",
        "Rebuilding with partial data availability"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 10 integrates mirroring (RAID 1) and striping (RAID 0), necessitating at least one operational drive in each mirror set to preserve data integrity across the striped array. With eight drives, a common setup might involve four mirror sets (e.g., four pairs of drives mirrored, then striped). If two drives fail within a single mirror set—meaning both drives in one pair are lost—that mirror set becomes non-functional because RAID 1 requires at least one drive to maintain the mirror. Since RAID 10 relies on all mirror sets being intact to stripe data across them, the loss of one entire mirror set renders the whole array inaccessible, as the striping cannot reconstruct data without all segments. The additional failure of a third drive in a different mirror set, while not immediately fatal by itself, does not alter the outcome: the array is already compromised by the first mirror set’s collapse. Consequently, the array fails entirely, resulting in total data loss unless mitigated by external backups or spares. \"Fully operational with reduced redundancy\" assumes all mirror sets remain partially functional, which isn’t true here due to the complete loss of one set. \"Degraded but still accessible with no redundancy\" might apply if only one drive per mirror set failed, preserving access, but losing both drives in one set exceeds RAID 10’s tolerance. \"Rebuilding with partial data availability\" requires a hot spare and a still-functional array to initiate rebuilding, neither of which is possible after a full mirror set failure. Thus, total failure is the accurate outcome."
    },
    {
      "id": 2,
      "question": "A virtualization host with dual 16-core CPUs runs 20 VMs, each with 4 vCPUs, and shows excessive CPU contention during peak loads. What’s the most effective initial mitigation?",
      "options": [
        "Add a third 16-core CPU to the host",
        "Reduce each VM’s vCPUs to 2",
        "Implement CPU affinity for high-priority VMs",
        "Increase hypervisor memory to reduce swapping"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The host has 32 physical cores (2 CPUs × 16 cores) and allocates 80 vCPUs (20 VMs × 4 vCPUs), yielding a 2.5:1 overcommitment ratio. While overcommitment is common in virtualization, a ratio this high can lead to contention during peak loads, where the hypervisor struggles to schedule all vCPUs onto available physical cores, increasing CPU ready times and degrading VM performance. Reducing each VM’s vCPUs to 2 lowers the total to 40 vCPUs, bringing the ratio to 1.25:1, which significantly alleviates contention by aligning virtual resources closer to physical capacity. This adjustment is immediate, cost-free, and directly tackles the root issue without requiring hardware changes or downtime. \"Add a third 16-core CPU to the host\" boosts capacity to 48 cores, reducing the ratio to 1.67:1, but it’s expensive, requires hardware procurement, and might not fully resolve contention if VM workloads remain unoptimized. \"Implement CPU affinity for high-priority VMs\" pins high-priority VMs to specific cores, potentially reducing their contention but leaving others to compete for remaining resources, and it sacrifices scheduling flexibility, making it less effective overall. \"Increase hypervisor memory to reduce swapping\" addresses swapping, which could exacerbate CPU load indirectly, but the scenario specifies contention, not memory shortages, making it irrelevant here. Reducing vCPUs is the most practical and impactful first step, balancing load efficiently."
    },
    {
      "id": 3,
      "question": "A server’s 10GbE interface exhibits intermittent packet drops under heavy load, with clean cables and correct MTU settings. What should you investigate first?",
      "options": [
        "Switch port buffer overflow",
        "NIC firmware incompatibility",
        "TCP offload engine settings",
        "Switch QoS throttling policies"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Intermittent packet drops during heavy load, despite verified cables and MTU, suggest a network bottleneck tied to traffic bursts rather than a persistent configuration error. Switch port buffer overflow occurs when incoming data exceeds the port’s buffer capacity, causing packets to drop as they can’t be queued—especially likely on a high-speed 10GbE link under intense load, where microbursts overwhelm small buffers. This is a common issue in high-throughput environments and aligns with the load-specific symptom. \"NIC firmware incompatibility\" could disrupt communication, but it typically causes consistent failures or logged errors, not intermittent drops tied to load, and no firmware issues are hinted at here. \"TCP offload engine settings\" involves NICs handling TCP processing; misconfiguration might affect performance or drop rates, but it’s less likely to produce intermittent, load-dependent drops without specific error codes. \"Switch QoS throttling policies\" might drop packets to enforce priority, but such policies would likely show predictable patterns tied to thresholds, not random intermittency. Investigating switch port buffers is the priority, as they directly manage traffic bursts, and tools like switch diagnostics or packet counters can confirm if buffers are maxing out under load."
    },
    {
      "id": 4,
      "question": "A disaster recovery plan mandates a 5-minute RTO for a mission-critical server. Which configuration meets this requirement?",
      "options": [
        "Hot site with synchronous replication",
        "Warm site with continuous backups",
        "Cloud cluster with real-time snapshots",
        "Cold site with asynchronous replication"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A 5-minute Recovery Time Objective (RTO) requires failover to a fully operational system within five minutes of an outage, demanding minimal setup and no significant data restoration delay. A hot site with synchronous replication keeps an identical, live secondary system in sync via real-time data mirroring, allowing immediate failover—typically within seconds—since the secondary site is already running and up-to-date. This setup ensures zero data loss (RPO of 0) and meets the tight RTO by avoiding boot or restore processes. \"Warm site with continuous backups\" maintains ready hardware and frequent backups, but restoring the latest backup and starting services could take 10–15 minutes or more, exceeding the 5-minute window due to file transfer and system initialization times. \"Cloud cluster with real-time snapshots\" offers rapid recovery potential, but applying snapshots and spinning up VMs often involves orchestration delays (e.g., network reconfiguration, instance provisioning), pushing recovery beyond 5 minutes. \"Cold site with asynchronous replication\" is the slowest, requiring hardware setup, data sync (lagged due to async), and boot time—potentially hours—making it incompatible with the RTO. Only the hot site with synchronous replication delivers the speed and readiness required for a 5-minute RTO."
    },
    {
      "id": 5,
      "question": "A server with redundant PSUs shuts down unexpectedly during a power surge, despite both PSUs being rated adequately. What’s the most likely cause?",
      "options": [
        "Both PSUs connected to the same unprotected circuit",
        "PSU firmware desync disrupting failover",
        "Surge exceeded PSU suppression capacity",
        "BIOS power management throttling output"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Redundant PSUs are designed to maintain power by drawing from independent sources, ensuring uptime if one fails or its input is disrupted. If both PSUs are connected to the same circuit without surge protection (e.g., no UPS or surge suppressor), a single power surge can overload that circuit, cutting power to both PSUs simultaneously and causing the server to shut down. This defeats the redundancy, as the failure occurs upstream of the PSUs rather than within them, and the lack of protection amplifies the surge’s impact. \"PSU firmware desync disrupting failover\" might prevent seamless failover between PSUs, but it’s unlikely to cause a total shutdown during a surge unless both units fail concurrently, and no firmware mismatch is indicated. \"Surge exceeded PSU suppression capacity\" suggests the PSUs’ internal surge protection failed, but ‘adequately rated’ implies they’re designed for typical surges; without specifics on surge magnitude, this is less probable. \"BIOS power management throttling output\" could reduce power draw under load, but it wouldn’t trigger a shutdown during a surge unless misconfigured to cut power entirely, which isn’t suggested here. The shared, unprotected circuit is a common oversight in redundancy planning, making it the most likely explanation given the surge context."
    },
    {
      "id": 6,
      "question": "SSH access to a server fails with ‘connection timed out’ after a network reconfiguration, but ping succeeds. What should you check first?",
      "options": [
        "Server firewall rules for port 22",
        "SSH service status on the server",
        "Network switch ACLs post-reconfig",
        "Client SSH configuration settings"
      ],
      "correctAnswerIndex": 2,
      "explanation": "A ‘connection timed out’ error means the client can’t reach the SSH service on port 22 within the timeout period, often indicating a network block, yet ping succeeding confirms basic IP reachability via ICMP. The network reconfiguration is the key clue: switch Access Control Lists (ACLs) might have been updated to block port 22 traffic, a common security measure, while leaving ICMP unhindered. This would prevent SSH packets from reaching the server, causing the timeout, and aligns with the timing of the issue. \"Server firewall rules for port 22\" could block port 22, but without mention of server-side changes, the network reconfig takes precedence as the trigger. \"SSH service status on the server\" being down typically results in ‘connection refused’ if the port isn’t listening, not ‘timed out,’ and ping success suggests the server is operational. \"Client SSH configuration settings\" might cause authentication or protocol errors, but ‘timed out’ points to a network issue, not a client misstep, especially post-reconfig. Checking switch ACLs first targets the most probable change-related cause, verifiable via switch logs or port filters."
    },
    {
      "id": 7,
      "question": "A RAID 6 array with ten drives loses four drives simultaneously due to a backplane failure. What’s the operational outcome?",
      "options": [
        "Operational with severe performance degradation",
        "Accessible in critical mode with data intact",
        "Completely failed with total data loss",
        "Partially operational with data corruption"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 6 uses dual parity to tolerate up to two simultaneous drive failures, reconstructing data from the remaining drives using parity calculations. With ten drives, the array can operate with eight drives intact (n-2), but losing four drives exceeds this limit, as parity can’t compensate beyond two losses. A backplane failure affecting four drives simultaneously—perhaps due to a shared connector or power issue—means the array lacks sufficient data and parity to rebuild or access any information, leading to complete failure and total data loss absent external backups. \"Operational with severe performance degradation\" might apply to RAID 5 with one failure, but RAID 6 has no degraded mode beyond two drives. \"Accessible in critical mode with data intact\" implies a state like RAID 5’s single-failure tolerance, but RAID 6 shuts down entirely past its threshold, with no ‘critical mode’ defined. \"Partially operational with data corruption\" suggests some data remains readable, but losing 40% of a RAID 6 array ensures no cohesive data set survives due to parity distribution. The simultaneous four-drive loss seals the array’s fate as completely failed."
    },
    {
      "id": 8,
      "question": "A server’s performance monitor reveals high disk latency despite low IOPS and ample CPU/RAM capacity. What’s the first hardware component to investigate?",
      "options": [
        "Disk controller’s cache settings",
        "Physical disk spindle speed",
        "SAS/SATA interconnect bandwidth",
        "Server’s PCIe bus throughput"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High disk latency with low IOPS (Input/Output Operations Per Second) and sufficient CPU/RAM indicates delays in servicing disk requests, not throughput or system resource shortages. The disk controller’s cache settings are pivotal: if write-back caching is disabled or the cache is too small, every I/O operation may go directly to the physical disk, bypassing buffering that reduces latency, even at low IOPS. This could stem from a conservative config (e.g., write-through mode for data safety) or a cache malfunction, both of which inflate latency by eliminating the controller’s ability to stage data efficiently. \"Physical disk spindle speed\" impacts HDD seek times, but low IOPS suggests minimal disk activity, and modern servers often use SSDs (no spindles), reducing its relevance. \"SAS/SATA interconnect bandwidth\" limits max data transfer, not latency at low load, unless saturated—which low IOPS contradicts. \"Server’s PCIe bus throughput\" could bottleneck high-IOPS scenarios, but with low IOPS, it’s not stressed. The controller cache is the first suspect, as it directly governs latency by managing how quickly requests are processed, verifiable via controller settings or diagnostics."
    },
    {
      "id": 9,
      "question": "A server room’s biometric access system fails, defaulting to unlocked. What’s the immediate mitigation?",
      "options": [
        "Station security personnel at the entrance",
        "Lock individual server racks",
        "Disconnect critical servers from the network",
        "Shut down non-essential servers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A biometric system failing open compromises physical security, granting unrestricted access to the server room. The immediate priority is to restore access control to prevent unauthorized entry, and stationing security personnel at the entrance achieves this swiftly by manually verifying identities, mimicking the biometric system’s intent without downtime or reconfiguration. \"Lock individual server racks\" secures individual servers but doesn’t stop intruders from entering the room, leaving equipment vulnerable to theft or tampering before reaching the racks. \"Disconnect critical servers from the network\" protects data from network attacks post-breach but disrupts operations and doesn’t address physical access, allowing damage or theft to occur unchecked. \"Shut down non-essential servers\" reduces risk to non-essential systems but leaves critical ones exposed and interrupts services unnecessarily. Security personnel provide a proactive, non-disruptive solution, maintaining control until the biometric system is fixed, aligning with urgency and practicality."
    },
    {
      "id": 10,
      "question": "Network latency spikes during backups despite ample bandwidth and low CPU usage. What should you check first?",
      "options": [
        "Backup application’s compression settings",
        "Server’s NIC teaming configuration",
        "Switch’s QoS policies",
        "Backup server’s disk I/O"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Latency spikes during backups, with sufficient bandwidth and low CPU usage, point to a network-level issue rather than server or application resource constraints. Switch Quality of Service (QoS) policies could be prioritizing other traffic or throttling backup flows, introducing delays as backup packets queue behind higher-priority data, even if bandwidth isn’t fully utilized. This fits the symptom of latency spikes occurring specifically during backups, as QoS can dynamically adjust based on traffic type or time. \"Backup application’s compression settings\" increases CPU load and reduces data size, potentially lowering bandwidth use, but doesn’t directly cause network latency unless misconfigured to bottleneck throughput, which low CPU usage contradicts. \"Server’s NIC teaming configuration\" affects load balancing or redundancy; misconfiguration might reduce bandwidth, but latency spikes without bandwidth saturation suggest a policy issue over hardware setup. \"Backup server’s disk I/O\" could slow backup creation, but latency is a network metric here, and disk bottlenecks would likely raise CPU or IOPS, not just network delays. Checking QoS policies first targets the network’s traffic management, verifiable via switch config or monitoring tools."
    },
    {
      "id": 11,
      "question": "A Linux server’s ZFS pool slows significantly after enabling deduplication. What’s the primary cause?",
      "options": [
        "Increased CPU overhead from dedup computations",
        "Insufficient RAM for dedup tables",
        "Disk I/O contention from metadata operations",
        "Network latency affecting remote dedup"
      ],
      "correctAnswerIndex": 1,
      "explanation": "ZFS deduplication identifies and eliminates redundant data blocks, requiring a deduplication table (DDT) in RAM to track unique block references. Enabling dedup significantly increases RAM demand, as DDT size scales with data volume (e.g., 1–5 GB per TB of unique data). Insufficient RAM forces ZFS to spill DDTs to disk, triggering frequent reads and writes to slower storage, which drastically slows performance due to I/O latency—often by orders of magnitude. This is a well-documented ZFS pitfall, where underestimating RAM needs cripples efficiency. \"Increased CPU overhead from dedup computations\" rises with dedup hash calculations, but modern CPUs handle this unless overloaded, and the scenario doesn’t indicate CPU limits. \"Disk I/O contention from metadata operations\" occurs as a byproduct of DDT disk access but isn’t the root cause; sufficient RAM would mitigate this. \"Network latency affecting remote dedup\" applies only to distributed setups, not implied here. Insufficient RAM is the primary bottleneck, directly causing the slowdown."
    },
    {
      "id": 12,
      "question": "A server’s CMOS battery fails, but it boots normally. What’s the most immediate impact?",
      "options": [
        "Time and date reset on reboot",
        "RAID configuration loss",
        "SSL certificate expiration",
        "Application license invalidation"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The CMOS battery maintains the real-time clock (RTC) and BIOS settings when the server is powered off. A dead battery means the RTC loses power, resetting the system time to a default (e.g., January 1, 2000, 00:00) on each reboot, even if the server boots normally using cached settings or OS time sync during operation. This impacts logs, scheduled tasks, and time-sensitive protocols like Kerberos immediately upon restart. \"RAID configuration loss\" is unlikely, as RAID settings are typically stored on the controller or drives, not CMOS. \"SSL certificate expiration\" depends on issuance dates, not server time, though incorrect time might cause validation errors later—not immediate. \"Application license invalidation\" could occur with time-based licenses, but it’s a downstream effect, not the first impact. Time reset is the direct, immediate consequence of CMOS failure."
    },
    {
      "id": 13,
      "question": "An active-active cluster experiences split-brain syndrome during a network partition. What’s the root cause?",
      "options": [
        "Quorum disk failure",
        "Network partition between nodes",
        "Misconfigured failover policies",
        "Low CPU resources on nodes"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Split-brain syndrome in an active-active cluster occurs when nodes lose communication but continue operating independently, each assuming the other is down and potentially corrupting data by acting as primary. A network partition—where nodes can’t exchange heartbeats or quorum votes due to a network failure—directly causes this by isolating nodes, breaking the cluster’s coordination mechanism. The scenario specifies this condition, making it the root cause. \"Quorum disk failure\" could lead to split-brain if nodes can’t access a shared quorum resource, but the network partition is the explicit trigger here. \"Misconfigured failover policies\" might cause improper transitions, but split-brain requires a communication loss, not just policy errors. \"Low CPU resources on nodes\" impacts performance, not cluster integrity. The network partition is the fundamental issue, emphasizing the need for redundant heartbeat links."
    },
    {
      "id": 14,
      "question": "An iSCSI connection drops during high I/O bursts, with stable network and SAN health. What should you adjust first?",
      "options": [
        "Increase iSCSI timeout values",
        "Update HBA firmware",
        "Check SAN LUN queue depth",
        "Verify network MTU alignment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "iSCSI connections rely on timeouts to detect unresponsive targets; if a high I/O burst delays responses beyond this threshold, the initiator drops the connection, mistaking it for a failure. Increasing timeout values (e.g., from 30 to 60 seconds) gives the SAN more time to handle bursts, preventing premature drops, especially when network and SAN health are stable. \"Update HBA firmware\" might resolve compatibility or stability issues, but without errors, it’s not the first step. \"Check SAN LUN queue depth\" limits concurrent I/O commands; adjusting it could help performance but doesn’t directly prevent timeout drops. \"Verify network MTU alignment\" ensures packet efficiency; misalignment causes fragmentation, but stability suggests it’s correct. Raising timeouts is the most immediate, targeted fix for burst-related drops."
    },
    {
      "id": 15,
      "question": "A DR plan requires a 30-minute RPO for a database. What’s the most reliable backup method?",
      "options": [
        "Hourly incremental backups",
        "Real-time transaction log shipping",
        "Daily full with differentials",
        "15-minute VM snapshots"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A 30-minute Recovery Point Objective (RPO) limits data loss to 30 minutes. Real-time transaction log shipping continuously sends database logs to a standby server, replicating changes nearly instantly (seconds), ensuring an RPO well under 30 minutes with minimal data loss. \"Hourly incremental backups\" risks losing up to an hour of data, exceeding the RPO. \"Daily full with differentials\" could lose a day’s worth, far beyond 30 minutes. \"15-minute VM snapshots\" captures VM states but isn’t a true backup, potentially missing transactions between snapshots, though it’s close to the RPO. Log shipping is the most reliable, database-specific method for tight RPOs."
    },
    {
      "id": 16,
      "question": "A server logs frequent ‘page fault’ errors, but memory usage is moderate. What’s the first check?",
      "options": [
        "Insufficient RAM causing excessive paging",
        "Corrupted application binaries",
        "Faulty swap space on disk",
        "Misconfigured virtual memory settings"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Page faults occur when a process requests memory not in RAM, forcing the OS to fetch it from disk-based virtual memory. Frequent faults with moderate usage suggest the active working set exceeds physical RAM, causing excessive paging to disk, even if total usage isn’t high—perhaps due to many processes or poor memory allocation. \"Corrupted application binaries\" might crash apps or log specific errors, not generic faults. \"Faulty swap space on disk\" could cause I/O errors, not just faults. \"Misconfigured virtual memory settings\" might limit swap, but moderate usage implies it’s active. Checking RAM sufficiency against workload is the first step."
    },
    {
      "id": 17,
      "question": "A Fibre Channel SAN link fails after a SAN switch firmware update, with no other changes. What’s the first check?",
      "options": [
        "SAN switch zoning configuration",
        "HBA driver compatibility with new firmware",
        "Fibre cable integrity",
        "SAN LUN masking settings"
      ],
      "correctAnswerIndex": 1,
      "explanation": "A SAN switch firmware update can alter communication protocols or behavior, potentially breaking compatibility with existing HBA drivers, leading to link failure. Checking driver compatibility with the new firmware version is the first step, as the timing ties directly to the update. \"SAN switch zoning configuration\" defines access paths; an update might reset it, but this isn’t typical. \"Fibre cable integrity\" is unrelated to firmware unless physically disturbed. \"SAN LUN masking settings\" controls visibility, not affected by switch firmware. Driver compatibility is the most immediate suspect."
    },
    {
      "id": 18,
      "question": "NIC teaming with LACP is configured, but traffic is not balancing across links. What should you adjust first?",
      "options": [
        "Switch to active-passive teaming mode",
        "Change the LACP hashing algorithm",
        "Modify the NIC’s duplex settings",
        "Reconfigure switch port channels"
      ],
      "correctAnswerIndex": 1,
      "explanation": "LACP balances traffic using a hashing algorithm (e.g., IP or MAC pairs). Uneven balancing suggests the algorithm (e.g., source/dest IP) hashes most flows to one link. Changing it to include more variables (e.g., ports) redistributes traffic. \"Switch to active-passive teaming mode\" eliminates balancing entirely. \"Modify the NIC’s duplex settings\" affects speed, not distribution. \"Reconfigure switch port channels\" might fix setup errors, but if the channels are correctly formed, the hashing algorithm is the key to balancing."
    },
    {
      "id": 19,
      "question": "A PowerShell script fails with ‘access denied’ when run remotely, but works locally. What’s the first check?",
      "options": [
        "Remote firewall rules",
        "PowerShell execution policy",
        "User permissions on the remote server",
        "PowerShell remoting configuration"
      ],
      "correctAnswerIndex": 2,
      "explanation": "‘Access denied’ remotely but not locally indicates a permission issue specific to remote execution. The user may lack rights to run scripts or access resources on the remote server, requiring elevated privileges or delegation. \"Remote firewall rules\" would block the connection or ports, not yield an access-denied error once connected. \"PowerShell execution policy\" applies locally and remotely; local success rules it out if the same policy is enforced. \"PowerShell remoting configuration\" enables remote access but doesn’t grant permissions. User rights are the key difference."
    },
    {
      "id": 20,
      "question": "A RAID 5 array with SSDs shows slower-than-expected read performance. What’s the likely cause?",
      "options": [
        "SSDs not optimized for sequential reads",
        "RAID controller missing read-ahead cache",
        "Large stripe size configuration",
        "SATA connection instead of NVMe"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 5 read performance suffers without a controller read-ahead cache, which prefetches data to reduce latency. Missing this, each read hits the disks directly, slowing access despite SSD speed. \"SSDs not optimized for sequential reads\" typically affects write performance more than read. \"Large stripe size configuration\" impacts write efficiency and fragmentation more than straightforward reads. \"SATA connection instead of NVMe\" can limit maximum throughput, but SSDs on SATA generally still exceed typical RAID 5 mechanical expectations. The read-ahead cache is the key factor here."
    },
    {
      "id": 21,
      "question": "A firewall allows only HTTPS traffic, but web applications are down. What’s the first check?",
      "options": [
        "SSL certificate validity",
        "Firewall rules for port 443",
        "Network interface status",
        "Web server service status"
      ],
      "correctAnswerIndex": 3,
      "explanation": "If HTTPS (port 443) is allowed but apps are down, the web server service might be stopped or crashed, preventing responses. \"SSL certificate validity\" causes trust errors, not outright downtime. \"Firewall rules for port 443\" are confirmed open in the scenario. \"Network interface status\" would block all traffic if down, including pings. Checking the web server service status is the most direct cause of the applications being inaccessible."
    },
    {
      "id": 22,
      "question": "A server crashes intermittently after a RAM upgrade, with memory errors in logs. What’s the first step?",
      "options": [
        "Update BIOS firmware",
        "Test new RAM modules individually",
        "Increase virtual memory allocation",
        "Replace the motherboard"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Memory errors post-upgrade suggest a faulty new RAM module. Testing each individually identifies the culprit efficiently. \"Update BIOS firmware\" might fix compatibility, but isolating hardware faults is more direct. \"Increase virtual memory allocation\" doesn’t address a physical RAM defect. \"Replace the motherboard\" is too drastic without confirming the RAM modules themselves. Testing modules individually is the priority."
    },
    {
      "id": 23,
      "question": "VMs with NAT networking can communicate internally but not externally, while the host can. What’s the first check?",
      "options": [
        "Guest OS firewall settings",
        "Hypervisor NAT configuration",
        "Switch VLAN settings",
        "Server routing table"
      ],
      "correctAnswerIndex": 1,
      "explanation": "NAT in hypervisors routes VM external traffic. If VMs can’t reach outside but the host can, the NAT config might lack proper outbound rules. \"Guest OS firewall settings\" could block some traffic, but the scenario suggests a broader NAT break. \"Switch VLAN settings\" and \"Server routing table\" typically affect traffic at the network layer, but NAT specifically is the translation layer. Checking the hypervisor NAT configuration is the first step."
    },
    {
      "id": 24,
      "question": "Backups fail due to insufficient space on the target, despite compression and deduplication enabled. What should you adjust first?",
      "options": [
        "Increase target storage capacity",
        "Reduce backup retention period",
        "Disable compression to free resources",
        "Split backups into smaller jobs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reducing retention deletes older backups, freeing space quickly without requiring additional hardware. \"Increase target storage capacity\" is a valid long-term solution but may involve procurement delays. \"Disable compression to free resources\" would actually increase the needed backup space. \"Split backups into smaller jobs\" spreads the data, but doesn’t reduce total storage requirements. Adjusting retention is the most immediate and efficient fix."
    },
    {
      "id": 25,
      "question": "Ping to a remote host succeeds, but SSH fails with ‘connection refused.’ What’s the likely cause?",
      "options": [
        "Remote firewall blocking port 22",
        "Server SSH client misconfiguration",
        "High network latency",
        "Remote SSH service not running"
      ],
      "correctAnswerIndex": 3,
      "explanation": "‘Connection refused’ means port 22 is reachable but there’s nothing listening on that port, strongly indicating the SSH service is down. \"Remote firewall blocking port 22\" typically causes timeouts, not refusals. \"Server SSH client misconfiguration\" would result in authentication or protocol errors. \"High network latency\" might slow responses, but not refuse connections. A non-running SSH service is the direct cause."
    },
    {
      "id": 26,
      "question": "Disk performance is slow despite low IOPS and sufficient bandwidth. What should you investigate first?",
      "options": [
        "Disk latency and queue depth",
        "CPU usage during disk operations",
        "Network bandwidth saturation",
        "RAM paging rates"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Slow performance with low IOPS suggests each operation takes too long, indicating high latency or long queue times. \"CPU usage during disk operations\" would be relevant if the system were CPU-bound. \"Network bandwidth saturation\" is unrelated to local disk unless it’s a remote storage scenario not indicated here. \"RAM paging rates\" refers to memory swapping, but the question focuses specifically on disk performance. Checking disk latency and queue depth is the logical first step."
    },
    {
      "id": 27,
      "question": "A biometric access system fails, defaulting to open. What’s the best temporary fix?",
      "options": [
        "Station guards at the door",
        "Lock server racks",
        "Disconnect critical servers",
        "Use temporary keycards"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Guards ensure immediate access control when a biometric system fails open. \"Lock server racks\" only secures the servers themselves, leaving other risks (like theft of peripheral gear). \"Disconnect critical servers\" addresses data security but not physical access. \"Use temporary keycards\" could work but typically requires time to provision and distribute. Posting security personnel is the fastest, most direct solution."
    },
    {
      "id": 28,
      "question": "A RAID 10 array with eight drives loses three drives across different mirror sets. What’s the status?",
      "options": [
        "Fully operational with reduced redundancy",
        "Degraded but still accessible with no redundancy",
        "Completely failed with total data loss",
        "Rebuilding with partial data availability"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 10 with eight drives (four mirror sets) losing one drive per set (three total) remains functional but degraded, as each set still has one operational drive. This results in no remaining redundancy, because any further failure in a set that’s lost a disk will cause total data loss in that set. \"Fully operational with reduced redundancy\" might suggest some parity or partial mirror remains, but here all used redundancy is gone in those three sets. \"Completely failed with total data loss\" would require at least one entire mirror set losing both drives. \"Rebuilding with partial data availability\" implies a hot spare or an ongoing rebuild, which isn’t possible here unless you replace drives immediately and start the rebuild. The array is simply degraded but still accessible."
    },
    {
      "id": 29,
      "question": "A valid HTTPS certificate triggers ‘untrusted’ warnings on clients. What’s the first check?",
      "options": [
        "Server time and date",
        "Certificate issuing authority chain",
        "Server IP configuration",
        "Client browser settings"
      ],
      "correctAnswerIndex": 1,
      "explanation": "‘Untrusted’ warnings often mean the client cannot verify the certificate’s authenticity because the intermediate or root CA chain is missing or unrecognized. \"Server time and date\" being incorrect typically triggers expiry or validity period errors, not an untrusted authority. \"Server IP configuration\" impacts connectivity, not certificate trust. \"Client browser settings\" might block certain CAs, but the missing or incomplete certificate chain is the most common cause. Checking the certificate authority chain is therefore the first step."
    },
    {
      "id": 30,
      "question": "Fans run at maximum speed despite normal temperatures. What’s the first check?",
      "options": [
        "BIOS fan control settings",
        "Temperature sensor calibration",
        "PSU voltage stability",
        "Dust buildup on components"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Faulty or misread temperature sensors can report abnormally high temperatures to the system, prompting the fans to run at full speed as a failsafe. \"BIOS fan control settings\" matter, but if temperatures are erroneously high, the BIOS won’t override sensor data. \"PSU voltage stability\" might cause other symptoms like random reboots, not sustained max fan speeds. \"Dust buildup on components\" can cause real overheating, but the question specifies normal temperatures, pointing to incorrect sensor data rather than actual thermal issues."
    }
  
