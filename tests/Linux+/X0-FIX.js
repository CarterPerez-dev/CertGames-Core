db.tests.insertOne({
  "category": "linuxplus",
  "testId": 10,
  "testName": "Linux+ Practice Test #10 (Ultra Level)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A system with SELinux in enforcing mode runs a custom binary from /usr/local/bin. Although the binary has correct file permissions, it immediately fails with an 'Access denied' error. All other binaries in the same directory run normally. Which microscopic detail BEST explains this issue?",
      "options": [
        "The binary has the wrong extended attributes, preventing execution in that context.",
        "The binary's MD5 checksum in /etc/selinux/targets is missing.",
        "The system requires a matching context in /etc/fstab to allow execution in /usr/local/bin.",
        "The binary has a group ownership mismatch, triggering a SELinux kill signal."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Even if file permissions and ownership are correct, SELinux requires proper context labeling. If the extended attributes (security.selinux) mismatch the policy for /usr/local/bin executables, SELinux will block execution.",
      "examTip": "Use `chcon` or `restorecon` to correct the SELinux label. Then verify by running `ls -Z` on the file."
    },
    {
      "id": 2,
      "question": "A container with a microservices-based application is consistently restarting. Docker logs show no helpful info. The container is ephemeral and uses a read-only root filesystem. Which minuscule oversight is MOST likely causing repeated failures?",
      "options": [
        "The container sets the environment variable HOME=/home/app, but that path is missing from the final image.",
        "The container uses CAP_NET_BIND_SERVICE to bind a privileged port, but no EXPOSE directive is present.",
        "The container attempts to write logs to /var/log inside the container, but /var/log is not writable with a read-only root.",
        "The container’s healthcheck is referencing an external service on a private network segment that doesn’t exist."
      ],
      "correctAnswerIndex": 2,
      "explanation": "In a read-only root filesystem, attempting to write logs to standard system paths like /var/log will cause errors. This subtlety can lead to immediate container exits or restarts.",
      "examTip": "For ephemeral containers, either redirect logs to stdout or mount a writable volume for logs."
    },
    {
      "id": 3,
      "question": "An admin attempts to rebase a Git branch with sensitive commits. After rebasing, the commits reappear in the repository's reflog. Which advanced nuance about Git causes the hidden commits to linger?",
      "options": [
        "The user forgot to run 'git commit --amend' to finalize the rebase changes.",
        "Git does not remove commits from reflog until a garbage collection or expiration occurs.",
        "The rebasing procedure automatically merges commits back if they have the same author.",
        "Tagging commits ensures they cannot be pruned without removing the tag references."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Git keeps commits in the reflog for potential recovery. Only after git garbage-collects or the reflog expires do those commits vanish permanently, even if they've been 'removed' by rebase.",
      "examTip": "Use `git gc --prune=now --aggressive` carefully if you must permanently remove sensitive commits."
    },
    {
      "id": 4,
      "question": "A sysadmin configures multiple NFS mounts in /etc/fstab using the 'soft' mount option to reduce client hangs. Under heavy load, the server sees sudden file corruption on the client side. Which subtle technical detail is MOST likely responsible?",
      "options": [
        "The 'soft' option introduces a keepalive mismatch with the server, causing partial writes.",
        "TCP is forced to use half-duplex mode on 'soft' mounts, leading to incomplete data integrity checks.",
        "'soft' NFS mounts can time out mid-operation, resulting in incomplete write operations on the client.",
        "The 'intr' mount option must be paired with 'soft' to ensure data integrity under heavy I/O."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A soft NFS mount can time out during write operations, risking partial writes and corruption. Hard mounts are typically recommended to ensure data integrity despite potential blocking issues.",
      "examTip": "Use 'soft' with caution. Data-critical applications almost always prefer 'hard' mounts."
    },
    {
      "id": 5,
      "question": "An orchestration script configures ephemeral containers behind a load balancer. The containers share an overlay network. Occasionally, a container logs that it cannot resolve the service name of a sibling container. All containers are healthy otherwise. Which minuscule oversight might cause intermittent DNS failures?",
      "options": [
        "The containers do not have IPv6 addresses, causing DNS to randomly fail for IPv4 lookups.",
        "Docker’s default DNS cache is disabled if containers are not run with --dns=<server> explicitly.",
        "One container is missing an exposed port in the Dockerfile, causing DNS resolution collisions.",
        "Short-lived containers can deregister from the embedded DNS quickly, resulting in stale queries."
      ],
      "correctAnswerIndex": 3,
      "explanation": "When a container stops or redeploys quickly, the overlay network DNS might briefly hold a stale record or fail to re-register the new container. This subtle timing can cause intermittent resolution errors.",
      "examTip": "Load balancers can mask ephemeral changes, but DNS within the overlay must keep up with container lifecycle events."
    },
    {
      "id": 6,
      "question": "A developer sees that an LVM volume is still showing high usage after deleting all files within it. Which microscopic cause is the likeliest reason the space wasn't reclaimed?",
      "options": [
        "The filesystem is journaling changes, requiring a remount to finalize freed space.",
        "Deleted files are still held open by a running process, so the data remains allocated.",
        "The volume's superblock is corrupted, preventing LVM from recognizing free space.",
        "The volume was formatted with btrfs subvolumes, so LVM doesn't track data usage."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Even if files are deleted, if a process has them open, the space remains allocated until the process releases them. This subtle nuance is common in log files or ephemeral data usage.",
      "examTip": "Use `lsof +L1` to find processes holding deleted files open."
    },
    {
      "id": 7,
      "question": "A container image is built with multiple RUN instructions. The final image size is unexpectedly large. Which near-identical nuance is the MOST likely reason?",
      "options": [
        "Each RUN line leads to an additional layer that retains the intermediate package data.",
        "Using a FROM scratch base image triggers repeated caching of system libraries in each layer.",
        "The Dockerfile references a custom ENTRYPOINT that adds extra overhead to every layer.",
        "Excessive environment variables are copied into each RUN instruction, doubling the final size."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Each RUN instruction in Docker results in a new layer. If package manager caches or temporary files are not cleared within the same RUN, they persist in intermediate layers, inflating the image size.",
      "examTip": "Combine package installation and cleanup into a single RUN step or use multi-stage builds to minimize final image size."
    },
    {
      "id": 8,
      "question": "A custom firewall script uses nft to accept inbound traffic on TCP port 443. Despite the script running successfully, remote clients still time out on port 443. All other ports are accessible. Which subtle misconfiguration is likely the culprit?",
      "options": [
        "The accept rule is appended instead of inserted, placing it below a drop rule with higher priority.",
        "The script is referencing ip6 filter table but ignoring IPv4 packets for port 443.",
        "The script sets the default policy to DROP in the output chain rather than the input chain.",
        "The system’s SSH port was changed to 443, conflicting with the new accept rule."
      ],
      "correctAnswerIndex": 0,
      "explanation": "In nftables, if a drop rule appears above the accept rule, traffic is dropped before reaching the accept. Appending the accept rule places it at the end of the chain, effectively overshadowed by the prior drop.",
      "examTip": "Ensure the correct rule ordering or priorities. 'insert' can place rules at specific indices if needed."
    },
    {
      "id": 9,
      "question": "A disk shows 'Input/output error' repeatedly, yet SMART checks pass. The admin tries different SATA cables and sees intermittent resolution. Which near-identical factor is the MOST probable cause?",
      "options": [
        "Misconfigured RAID metadata on the disk, leading to random read failures.",
        "A borderline insufficient power supply rail, causing random voltage drops under load.",
        "A missing partition label in /etc/fstab that triggers read errors after mounting.",
        "A mismatched GPT/MBR partition scheme preventing consistent block addressing."
      ],
      "correctAnswerIndex": 1,
      "explanation": "If the drive occasionally loses adequate power, it can cause sporadic I/O errors, even when SMART appears fine. Subtle power supply or cable issues often produce intermittent disk errors that vanish with a better supply or cable arrangement.",
      "examTip": "Always verify stable power rails for high-load disks. SMART won't necessarily reveal voltage fluctuations."
    },
    {
      "id": 10,
      "question": "PBQ: You suspect major throughput drops on an NFS mount. Place the commands in the correct order to diagnose the issue:\n1. iostat -xm 1\n2. nfsstat -r\n3. rpcinfo -p server\n4. mount | grep nfs",
      "options": [
        "2->1->3->4",
        "4->2->3->1",
        "1->4->3->2",
        "4->3->2->1"
      ],
      "correctAnswerIndex": 1,
      "explanation": "First verify how the share is mounted (4), then check server RPC services (3), examine NFS stats like retransmissions (2), and finally monitor disk I/O with iostat (1). This order isolates mount, server RPC, and then performance details.",
      "examTip": "Use nfsstat to see if high retrans or timeouts indicate networking or server load problems."
    },
    {
      "id": 11,
      "question": "Two ephemeral containers share the same Docker network. The first container tries to ping the second by container name. Sometimes it resolves, sometimes not. Which nearly indistinguishable nuance can cause such inconsistent name resolution?",
      "options": [
        "The Docker DNS internal cache flushes on container exit, which might happen if the container restarts frequently.",
        "Local firewall rules on the second container block ICMP traffic, preventing stable name resolution responses.",
        "The first container’s /etc/resolv.conf is overwritten on startup, forcing fallback to the system's host DNS.",
        "Docker service logs at the host show a 'DNS bridging mismatch' that forcibly breaks ephemeral container lookups."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the second container restarts or ephemeral containers churn quickly, the embedded DNS can briefly lose the name->IP mapping. This leads to intermittent resolution success or failure.",
      "examTip": "Using a stable container name or a user-defined bridge network can help maintain consistent name resolution."
    },
    {
      "id": 12,
      "question": "A critical script runs at midnight using cron. It randomly fails once every few weeks with 'sed: input file read error'. No recent package updates or permission changes are reported. Which subtle scenario might explain the error?",
      "options": [
        "The PATH variable in the cron environment omits /usr/bin, so sed occasionally isn't found.",
        "Logrotate triggers around midnight and competes for read access on the file, causing a transient read error.",
        "The script uses systemd-run, conflicting with the cron job's environment variables.",
        "The cronjob line has unescaped wildcards, substituting filenames in the script command sporadically."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Logrotate often runs around midnight and can temporarily move or truncate files, causing sed read errors if the script tries to read a log that logrotate is rewriting at the same time.",
      "examTip": "Check /etc/logrotate.d scheduling or offset times to avoid concurrency issues with nightly scripts."
    },
    {
      "id": 13,
      "question": "On a large multi-user system, the admin sees repeated 'cannot fork: resource temporarily unavailable' messages. Memory and swap appear sufficient. Which advanced factor is the root cause?",
      "options": [
        "The maximum number of user processes (ulimit -u) is reached, preventing new forks.",
        "A kernel memory leak in the VFS layer is causing partial reads on fork attempts.",
        "SELinux confines user processes to 512 child processes by default, hitting the limit.",
        "Systemd cgroup memory controllers are set incorrectly, capping memory usage artificially."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If memory is available but the system hits the maximum user processes limit, fork() calls fail with 'resource temporarily unavailable.' This subtlety is governed by ulimit -u or /etc/security/limits.conf.",
      "examTip": "For large multi-user systems, raise the nproc limit carefully, or rogue processes could degrade system stability."
    },
    {
      "id": 14,
      "question": "An admin replaced SSH with a custom variant compiled for FIPS compliance. Despite setting 'PasswordAuthentication no' and 'ChallengeResponseAuthentication no', users can still log in with a password. Which hairline detail is causing the mismatch?",
      "options": [
        "The custom SSH server references /etc/ssh/custom_sshd_config, ignoring /etc/ssh/sshd_config.",
        "System-wide PAM modules override the directive, permitting password-based keyboard-interactive logins.",
        "The user is a member of the wheel group, allowing forced password fallback regardless of the config.",
        "FIPS mode forces reversion to password-based authentication if the key length is under 4096 bits."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Even if 'PasswordAuthentication' is disabled in sshd_config, PAM can still allow keyboard-interactive logins unless that is also disabled. The subtlety is that password prompts can appear under the guise of keyboard-interactive.",
      "examTip": "Check /etc/pam.d/sshd or similar files to ensure password-based logins are truly disabled."
    },
    {
      "id": 15,
      "question": "A disk labeled as 'nfsbackup' is configured with Btrfs. The admin notices that snapshots of /nfsbackup are vastly increasing used space. Which subtle Btrfs feature might cause this discrepancy?",
      "options": [
        "Copy-on-write at the subvolume level is duplicating blocks for every read operation.",
        "Automatic compression is disabled, forcing snapshots to store entire file blocks individually.",
        "Btrfs is performing RAID1 internally, doubling the data usage for each snapshot.",
        "Deleted or modified files remain referenced by snapshots until those snapshots are removed."
      ],
      "correctAnswerIndex": 3,
      "explanation": "In Btrfs, snapshots reference the original blocks. Until snapshots are removed, those blocks can't be reclaimed, leading to seemingly higher used space. This is a subtle copy-on-write side effect.",
      "examTip": "Use `btrfs subvolume delete` or `btrfs subvolume list` to manage snapshots and free space."
    },
    {
      "id": 16,
      "question": "PBQ: Arrange these steps to identify which cgroup constraints are limiting a container’s memory usage:\n1. cat /sys/fs/cgroup/memory/<container_id>/memory.limit_in_bytes\n2. systemctl status docker\n3. docker inspect <container_id>\n4. grep Memory <docker_inspect_output>",
      "options": [
        "2->1->3->4",
        "1->2->4->3",
        "3->4->2->1",
        "3->4->1->2"
      ],
      "correctAnswerIndex": 2,
      "explanation": "First inspect the container (3), grep memory settings (4), then confirm cgroup memory limits in /sys/fs/cgroup (1). Checking docker’s overall status is a lesser final step (2).",
      "examTip": "Remember that container memory constraints appear in cgroup files under /sys/fs/cgroup, but you can also confirm them in the container’s Docker config."
    },
    {
      "id": 17,
      "question": "Users report that a newly deployed application in a systemd-nspawn container can’t access GPU resources. The GPU is recognized on the host. Which near-identical detail is the root cause?",
      "options": [
        "systemd-nspawn uses a read-only /sys path, preventing GPU driver loading.",
        "The container lacks the correct user namespace mapping for GPU device nodes in /dev.",
        "GPU support requires ephemeral overlay networks in systemd-nspawn that are disabled by default.",
        "X11 forwarding in systemd-nspawn is turned off by default, blocking GPU hardware acceleration."
      ],
      "correctAnswerIndex": 1,
      "explanation": "GPU devices reside in /dev/dri or similar nodes. Without proper device cgroup or user namespace mapping, the container can’t access those nodes. This subtle namespace issue is typical in container-like environments.",
      "examTip": "Use bind mounts or pass --property=DeviceAllow= for systemd-nspawn to allow GPU device usage."
    },
    {
      "id": 18,
      "question": "An admin extends an LVM volume for /home from 100GB to 150GB. The ext4 filesystem was resized with resize2fs. df now shows 150GB, but users still hit 'no space left on device' errors at ~120GB usage. Which subtle factor is the likely cause?",
      "options": [
        "Reserved blocks for root or journal are set to 20% of the filesystem, limiting user space.",
        "The ext4 journal is pinned to the older size, requiring an unmount and forced journal recreation.",
        "Inode exhaustion occurred because the original mkfs had insufficient inodes for large files.",
        "Quota is enforced at 120GB for each user in /etc/projects, ignoring the new capacity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Even though the filesystem was resized, if inodes are fully consumed, users encounter 'no space left on device' despite free blocks. Ext4 inodes are often set at mkfs time; resizing doesn’t add new inodes.",
      "examTip": "Monitor inodes with `df -i` or `stat -f`. If inodes are exhausted, the only solution is to reformat or remove unneeded files."
    },
    {
      "id": 19,
      "question": "A developer tries to secure a private container registry with TLS. They created a self-signed cert for registry.example.com and placed it in /etc/docker/certs.d/registry.example.com. Docker commands still fail with x509 certificate errors. Which nuance is correct?",
      "options": [
        "Docker requires a signed certificate from a recognized CA, so self-signed is always rejected.",
        "The directory name must match the registry’s hostname and port, e.g., registry.example.com:443.",
        "TLS in Docker only supports ECC certificates by default, so RSA self-signed certificates fail.",
        "The systemd-resolved service blocks custom certificates unless pinned in /etc/systemd/system."
      ],
      "correctAnswerIndex": 1,
      "explanation": "For Docker’s custom certs, the path must match the exact registry hostname:port. If the registry is on port 443, Docker expects the directory to be registry.example.com:443. Missing the port can cause errors even if the cert is correct.",
      "examTip": "Ensure the entire path matches <host>:<port>. If using default 443, you still often specify it in the folder name."
    },
    {
      "id": 20,
      "question": "A user’s system has a GPT disk with an EFI partition, but the firmware is set to Legacy (BIOS) mode. The system boots sporadically or not at all. Which microscopic mismatch likely explains the intermittent boot success?",
      "options": [
        "The BIOS emulation attempts to read the EFI partition as an MBR boot partition and sometimes fails.",
        "GPT partitions auto-convert to MBR in each power cycle, causing partial boot failures.",
        "A leftover core.img from Grub Legacy is interfering with the UEFI boot files on the partition.",
        "The system uses syslinux in GPT mode, requiring an additional ext4 partition for hybrid booting."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Legacy BIOS can’t reliably handle an EFI partition. Sometimes the BIOS finds a fallback bootloader in the Protective MBR, but it’s inconsistent. Full GPT/UEFI alignment is needed for stable boot.",
      "examTip": "For consistent booting, enable UEFI in firmware if the disk is GPT with an EFI partition or convert to a BIOS-friendly layout."
    },
    {
      "id": 21,
      "question": "PBQ: You need to diagnose a Docker container's CPU usage, memory usage, and the container’s cgroup path. Order these steps:\n1. docker top <container>\n2. cat /proc/<pid>/cgroup\n3. docker stats <container>\n4. ps -o pid,cmd -p <pid>",
      "options": [
        "1->3->4->2",
        "3->1->2->4",
        "1->4->2->3",
        "2->4->1->3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "First check running processes in the container (docker top), then use docker stats to see resource usage, confirm the host PID with ps, and finally view cgroup mapping in /proc/<pid>/cgroup.",
      "examTip": "docker stats is a quick way to see real-time resource usage for containers. For deeper analysis, compare with host-level tools."
    },
    {
      "id": 22,
      "question": "Which detail commonly causes 'Permission denied' when removing a file in a directory with SGID set for the group, even if the user is in that group and has rw permissions on the file?",
      "options": [
        "The sticky bit (t) is also set on the directory, requiring file ownership to delete.",
        "SGID disallows file deletion unless performed by the group owner explicitly.",
        "ACLs override standard group permissions, removing the write bit from directory entries.",
        "A systemd mount unit for the directory blocks user-level unlink operations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the directory has both SGID and the sticky bit set (e.g., drwxrwsT), only the owner of the file or root can delete it. Group membership alone isn’t enough in that scenario.",
      "examTip": "SGID ensures new files inherit group ownership. The sticky bit restricts deletion to the file’s owner or root."
    },
    {
      "id": 23,
      "question": "Even though the net.ipv4.ip_forward=1 is set, forwarded packets are never leaving the server. NAT is configured in iptables. Which near-invisible oversight might explain the inactivity?",
      "options": [
        "The systemd service 'network-online.target' is not reached, so ip_forward is ignored.",
        "RP filtering is enabled on the outbound interface, discarding forwarded packets from unknown subnets.",
        "The iptables FORWARD chain policy is ACCEPT, but the POSTROUTING chain remains set to DROP by default.",
        "A mismatched routing table entry for the default gateway is set to 'reject'."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reverse Path (RP) filtering can drop packets if their source network isn’t routed properly. It’s a subtle cause of silent forwarding failures, even if ip_forward=1 is set.",
      "examTip": "Check /proc/sys/net/ipv4/conf/*/rp_filter. Often disabling or adjusting rp_filter is required for advanced forwarding setups."
    },
    {
      "id": 24,
      "question": "A developer’s script forcibly uses /bin/sh, relying on advanced bash array syntax. The script partially works but breaks on array expansions. Which slight detail clarifies why this is happening?",
      "options": [
        "The script’s #! line is commented out by a preceding colon, ignoring the array syntax altogether.",
        "On Debian-based systems, /bin/sh typically points to dash, which does not support bash arrays.",
        "POSIX shells require 'enable arrays' prior to using them, so the developer must insert 'shopt -s arrays'.",
        "The script is run from cron, ignoring array assignments by default unless typed variables are declared."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Debian-based distros often link /bin/sh to dash, which lacks advanced bash features like arrays. This subtle difference in the default shell can break scripts relying on bash syntax.",
      "examTip": "Use #!/bin/bash if you need bash-specific features. POSIX dash is smaller and faster but has fewer features."
    },
    {
      "id": 25,
      "question": "BEST: A critical server with minimal downtime windows must update its kernel. Which advanced kernel patching option is BEST if no reboot can be scheduled soon?",
      "options": [
        "Use an LTS kernel with fewer vulnerabilities, deferring updates until the next planned reboot.",
        "Employ kexec for an immediate in-memory kernel reload, skipping BIOS initialization.",
        "Implement live kernel patching (kpatch or kernel livepatch) to apply changes at runtime.",
        "Compile a monolithic kernel with minimal modules to reduce the risk of vulnerabilities."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Live kernel patching (kpatch, kernel livepatch) allows applying critical fixes without rebooting, best addressing zero-downtime requirements. kexec still disrupts processes for a short time, LTS does not guarantee no vulnerabilities, and monolithic kernels do not circumvent the need for patching.",
      "examTip": "Live patch solutions are distro-specific. SUSE has kGraft, RHEL has kpatch, Ubuntu has Canonical Livepatch."
    },
    {
      "id": 26,
      "question": "A developer needs to incorporate a kernel module named xfrm_user for advanced IPsec on an Ubuntu server. It's compiled and present in /lib/modules. modprobe xfrm_user silently fails, but insmod xfrm_user.ko loads it. Which subtle difference explains this?",
      "options": [
        "insmod bypasses the module blacklist, whereas modprobe respects blacklists defined in /etc/modprobe.d.",
        "modprobe requires the kernel module signature, and xfrm_user.ko is not signed, so it’s ignored.",
        "Module xfrm_user must be appended to /etc/modules to be recognized by modprobe automatically.",
        "xfrm_user is a built-in kernel feature on Ubuntu, preventing modprobe from loading an external version."
      ],
      "correctAnswerIndex": 0,
      "explanation": "modprobe checks blacklists and dependencies. If xfrm_user is blacklisted somewhere in /etc/modprobe.d, modprobe will skip loading it silently. insmod loads the module directly without referencing blacklists.",
      "examTip": "Search for blacklists with `grep xfrm_user /etc/modprobe.d/*`. Removing the blacklist entry usually fixes modprobe failures."
    },
    {
      "id": 27,
      "question": "An admin sets up a Samba share with 'valid users = @marketing' in smb.conf. The marketing group can access the share, but a few marketing users still get 'Access denied.' They are indeed in the marketing group. Which subtle factor is blocking them?",
      "options": [
        "Samba only evaluates primary group membership by default, ignoring secondary groups like marketing.",
        "The marketing group is missing an entry in /etc/smbusers, so Samba refuses logins.",
        "The share is forcibly mapped to the 'nobody' user, preventing group-based membership from taking effect.",
        "The Samba server’s passdb backend is using an outdated cache that has not recognized new group members."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Some Samba configurations only check the user’s primary UNIX group, ignoring secondary groups. Users whose marketing membership is secondary can be denied. Alternatively, 'force group' or 'winbind' might be needed for correct group enumeration.",
      "examTip": "Check `id username` to see if marketing is primary or secondary. Samba might need extra settings to handle secondary groups."
    },
    {
      "id": 28,
      "question": "A performance test shows extremely high system CPU usage on a KVM host, but user CPU usage is minimal. The VMs themselves show no anomalies. Which advanced nuance is likely behind the high system usage on the host?",
      "options": [
        "Nested virtualization is enabled, causing the hypervisor to emulate multiple CPU rings simultaneously.",
        "A meltdown/spectre mitigation is triggered on every context switch, inflating system CPU cycles.",
        "The host kernel is compressing memory pages excessively for ballooning, driving system overhead.",
        "IO threads for virtio are pinned to CPU 0, saturating that core with kernel-level interrupts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Meltdown and Spectre mitigations can significantly increase kernel overhead due to more frequent context switching and address space isolation, showing up as high system CPU usage.",
      "examTip": "Check /sys/devices/system/cpu/vulnerabilities for meltdown/spectre status. Some mitigations can be toggled for performance trade-offs."
    },
    {
      "id": 29,
      "question": "An automation script runs a Docker Compose file. The script fails if the images are not already present locally. The Dockerfile is correct, and `docker-compose build` works manually. Which micro-level detail in the script might explain the failure?",
      "options": [
        "The script sets DOCKER_HOST to a remote daemon, ignoring local build caches.",
        "The script uses docker compose run instead of docker compose up, omitting build steps by default.",
        "An environment variable COMPOSE_HTTP_TIMEOUT is set too low, causing partial image downloads.",
        "The docker-compose.yml lacks an explicit 'build:' directive, so 'up' attempts to pull images instead."
      ],
      "correctAnswerIndex": 3,
      "explanation": "If the Compose file only specifies 'image:' and not 'build:', Docker Compose tries to pull the image from a registry, failing if it doesn’t exist. 'build:' instructs Compose to build from the local Dockerfile when the image is missing.",
      "examTip": "Ensure your compose services have both 'build:' and optionally 'image:' if you want to name the built image."
    },
    {
      "id": 30,
      "question": "PBQ: An admin wants to convert an existing ext4 filesystem to XFS without data loss. Arrange the logical steps:\n1. Create a new XFS partition\n2. Copy data from ext4 to XFS\n3. Mount the new XFS partition\n4. Update /etc/fstab to reference the new partition",
      "options": [
        "1->2->3->4",
        "3->1->2->4",
        "2->1->4->3",
        "1->3->2->4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "You must create the new XFS partition (1), then copy data (2), mount it (3), and update /etc/fstab (4). XFS doesn’t support in-place conversion from ext4, so a separate partition or device is needed.",
      "examTip": "Use rsync or a similar tool to copy. After verifying, repurpose the old partition if desired."
    },
    {
      "id": 31,
      "question": "A developer uses systemctl to start a user-level service but sees 'Failed to connect to bus: No such file or directory' when running from a chroot environment. Which advanced nuance explains the error?",
      "options": [
        "A chroot environment has no systemd PID 1, so user-level systemd daemons cannot connect to the D-Bus socket.",
        "The developer must specify the user's shell in chroot, or systemd cannot interpret commands.",
        "systemctl only works if the root shell is configured with /dev/pts mounted, which is absent in the chroot.",
        "The service file references a journald socket, which is not automatically bound inside a chroot environment."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Inside a minimal chroot, there’s no active systemd or D-Bus environment. systemctl depends on communicating with systemd over the bus, which doesn’t exist in a typical chroot scenario.",
      "examTip": "If you need a service in chroot, consider alternative approaches like running a minimal systemd-nspawn container or reconfiguring a separate init."
    },
    {
      "id": 32,
      "question": "A user sets 'alias lls=\"ls -l\"' in ~/.bashrc but finds it doesn’t work in scripts invoked with #!/bin/bash. Which subtle difference between interactive and non-interactive shells is relevant?",
      "options": [
        "Aliases only expand in interactive shells unless force-enabled with 'shopt -s expand_aliases' in the script.",
        "Bash aliases are overwritten by the system default /etc/bash.bashrc in non-interactive shells.",
        "Scripts using #!/bin/bash always ignore user-defined environment variables in ~/.bashrc.",
        "Non-interactive shells revert to dash, ignoring .bashrc by default on some distributions."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Non-interactive shells do not expand aliases by default. You can enable them with `shopt -s expand_aliases` or source the relevant config files in the script. It’s a subtle difference from interactive usage.",
      "examTip": "Aliases are mostly for interactive convenience. For scripts, consider using full commands or defining functions instead."
    },
    {
      "id": 33,
      "question": "A Kubernetes cluster uses flannel as the CNI plugin. Pods occasionally become unreachable from other nodes. The node’s flannel logs show repeated re-initialization messages. Which advanced reason might cause that ephemeral re-initialization?",
      "options": [
        "CoreDNS is repeatedly force-upgrading flannel, resetting its configuration each cycle.",
        "The etcd store that flannel relies on has transient connectivity issues, prompting flannel to restart.",
        "A misconfigured calico plugin conflicts with flannel, so both keep overwriting the cluster's overlay config.",
        "IPtables is auto-flushing NAT rules every hour, forcing flannel to re-apply routes and lose ephemeral connections."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Flannel typically gets its network config from etcd (or the Kubernetes API). If etcd connectivity is unstable, flannel re-initializes repeatedly. That breaks existing Pod routes temporarily.",
      "examTip": "Check etcd logs for cluster health. Unstable etcd is a leading cause of plugin re-init issues."
    },
    {
      "id": 34,
      "question": "An admin tries to enable the 'noatime' mount option for a large XFS volume to reduce overhead. After editing /etc/fstab and remounting, they see no performance gain. Which subtlety about XFS might be relevant?",
      "options": [
        "XFS defaults to relatime, making noatime effectively redundant for most workloads.",
        "XFS automatically forces atime updates for directories, ignoring user-specified noatime.",
        "XFS requires a special mkfs.xfs flag to enable noatime at formatting time, not mount time.",
        "The kernel patches for noatime are not present in the current distro’s XFS implementation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modern XFS defaults to relatime, which is nearly as efficient as noatime for most cases. Switching to noatime might not yield further gains, making the difference imperceptible.",
      "examTip": "Relatime updates atime only if it's older than the mtime or ctime, drastically reducing overhead compared to strict atime."
    },
    {
      "id": 35,
      "question": "A developer uses a multi-stage Docker build. The final stage references a file from an earlier stage but receives 'COPY failed: file not found in build context.' Which micro detail is correct?",
      "options": [
        "The FROM statements are reversed, so Docker tries to copy from the final stage into the base stage.",
        "Files in earlier stages are ephemeral unless explicitly exported with 'EXPORT ...' in the Dockerfile.",
        "COPY cannot directly reference another stage’s filesystem. The developer must use --from=<stage> in the COPY syntax.",
        "Multi-stage builds require the 'buildkit' directive to be enabled in /etc/docker/daemon.json, or cross-stage COPY fails."
      ],
      "correctAnswerIndex": 2,
      "explanation": "For multi-stage builds, you must specify the source stage with `COPY --from=<stage> /path /destination`. Standard COPY alone tries to copy from the local build context, not the preceding stage’s filesystem.",
      "examTip": "Example usage: `COPY --from=builder /app/bin /usr/local/bin` where 'builder' is the name of the earlier stage."
    },
    {
      "id": 36,
      "question": "During a security audit, an advanced user claims that enabling 'audit=1' on the kernel command line slowed down disk I/O. Which subtlety might confirm their suspicion?",
      "options": [
        "The kernel audit subsystem logs every single block device operation, drastically increasing overhead.",
        "Setting 'audit=1' forces synchronous journaling on ext4, leading to slower writes.",
        "The audit daemon enters debug mode automatically if the kernel param is set, flooding syslog with trace logs.",
        "The kernel replays the entire audit log in memory on each disk write to ensure data integrity."
      ],
      "correctAnswerIndex": 0,
      "explanation": "When 'audit=1' is set, the kernel can log a variety of system calls, including I/O operations. This can add significant overhead depending on the auditing rules. The other options are less likely or incorrect specifics.",
      "examTip": "Fine-tune audit rules to avoid unnecessary events, or consider alternative event tracing if performance is critical."
    },
    {
      "id": 37,
      "question": "A developer tries to use parted to resize a GPT partition from 500GB to 600GB. parted refuses, claiming 'not enough free space'. The underlying LVM PV on the same disk still has 200GB unallocated. Which subtle detail is causing parted to fail?",
      "options": [
        "parted sees the LVM signature and blocks resizing GPT partitions containing LVM data.",
        "The disk is near the 2TB limit for GPT, so parted rejects expansions for partial partitions.",
        "parted must be run in interactive mode (curses UI) to resize LVM partitions properly.",
        "LVM takes up slack space inside the partition; parted cannot see free space within the LVM."
      ],
      "correctAnswerIndex": 3,
      "explanation": "If LVM is using the partition, parted sees the partition as fully allocated, not the free space inside the LVM PV. parted cannot automatically adjust the GPT partition based on LVM’s internal free space.",
      "examTip": "You must shrink or expand the partition at the GPT level first (if actual disk space is free), then resize the LVM PV, or vice versa for the correct approach."
    },
    {
      "id": 38,
      "question": "Users on an Ubuntu 22.04 system experience 5+ second delays when starting new shells. strace reveals slow lookups in /etc/group. The file has thousands of group entries. Which hairline solution addresses the slowdown?",
      "options": [
        "Run 'nscd' to cache group lookups locally, bypassing repeated file scans.",
        "Convert the system to systemd-homed for more efficient user management.",
        "Recompile the kernel with an optimized getgrent() to handle large group files.",
        "Patch /etc/pam.d/login to skip group membership checks for interactive shells."
      ],
      "correctAnswerIndex": 0,
      "explanation": "nscd (or sssd) caches group lookups, reducing repeated linear scans of large /etc/group files. The other solutions are either partial or non-standard approaches.",
      "examTip": "Ensure nscd is properly configured. Alternatively, break up large group files or use an LDAP directory for more manageability."
    },
    {
      "id": 39,
      "question": "PBQ: You need to diagnose a kernel memory leak. Arrange these steps in the proper order:\n1. Use slabtop to examine kernel slab usage.\n2. Collect a crash dump with kdump.\n3. Compare /proc/meminfo before and after the issue.\n4. Inspect /var/crash for analysis with crash or drgn tools.",
      "options": [
        "3->1->2->4",
        "1->3->4->2",
        "2->4->1->3",
        "1->2->3->4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "First look at /proc/meminfo changes over time (3), then use slabtop to see if slab allocations are rising (1). If you confirm a kernel-level leak, gather a crash dump (2) and analyze it (4).",
      "examTip": "Kernel memory leaks often appear in slab caches. Tools like crash or drgn require a kernel dump to investigate thoroughly."
    },
    {
      "id": 40,
      "question": "A system’s journald log is flooded with bluetoothd entries, but the server has no Bluetooth hardware. Removing the bluetooth package does not stop the logs. Which subtle element might be overlooked?",
      "options": [
        "A stale systemd unit named bluetooth.service is still enabled, auto-starting a leftover binary.",
        "The kernel module for bluetooth is compiled in, forcing bluetoothd to run if discovered in /lib.",
        "An environment variable BLUETOOTH_DEBUG=1 in /etc/profile triggers verbose logging even if bluetooth is removed.",
        "SELinux contexts for the /var/log/journal directory cause repeated re-labeling events misattributed to bluetoothd."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Even if the package is gone, a leftover systemd unit might remain. If that unit references an existing binary or script, it can spam the logs. Disabling or masking bluetooth.service is often needed.",
      "examTip": "Use `systemctl list-unit-files | grep bluetooth` or check symlinks in /etc/systemd/system to ensure the service is truly disabled."
    },
    {
      "id": 41,
      "question": "A container orchestrator is configured to pull images from a private registry at registry.intranet:5000. Intermittently, it fails with 'no route to host', despite local tests from the host working. Which near-identical detail likely explains the network difference for the orchestrator?",
      "options": [
        "The orchestrator’s service runs in a separate cgroup with no network access to custom ports.",
        "A user-defined Docker network for the orchestrator excludes DNS resolution for registry.intranet.",
        "The orchestrator uses a different default gateway in a separate network namespace, missing the route to the registry.",
        "The local tests used IPv6 while the orchestrator is restricted to IPv4, causing route mismatch."
      ],
      "correctAnswerIndex": 2,
      "explanation": "If the orchestrator’s service is in a separate namespace with a different default route, the registry.intranet:5000 might be unreachable from that namespace. Local host-based tests can succeed while the orchestrator fails.",
      "examTip": "Network namespaces can differ from the host. Use `ip netns list` or similar commands to confirm routing in the orchestrator’s namespace."
    },
    {
      "id": 42,
      "question": "Direct: In a Docker context, which minimal nuance is required for mounting a host directory into a container with write permissions from the container side?",
      "options": [
        "Use --cap-add=SYS_ADMIN to allow read-write access from the container.",
        "Append the rw tag to -v, such as '-v /host/data:/container/data:rw'.",
        "Set the container’s user namespace to 'host' for matching UIDs.",
        "Include 'overlay2' as the storage driver to preserve the host’s permission bits."
      ],
      "correctAnswerIndex": 1,
      "explanation": "When binding a host directory, the default mode is read-write, but specifying ':rw' clarifies it. Without that, or if another mode is specified, write access might not be granted. Capabilities or the overlay driver are separate concerns.",
      "examTip": "Check if the user IDs inside the container map properly to host filesystem permissions. If not, you might need extra steps."
    },
    {
      "id": 43,
      "question": "A system administrator sets up a swap file on XFS using dd, updates /etc/fstab, and attempts swapon. It fails with 'swapon: /swapfile: swapon failed: Invalid argument.' Which overlooked XFS-specific nuance is correct?",
      "options": [
        "XFS must be mounted with the usrquota option for swap files to work properly.",
        "XFS does not support swap files without the 'nodiscard' mount option set.",
        "swap files on XFS require physically contiguous data, so you must use the swapon -f option to force allocation.",
        "XFS requires a special flag on the file or a 'reflink=0' attribute to allow swap files."
      ],
      "correctAnswerIndex": 3,
      "explanation": "XFS can create copy-on-write extents that break swap file contiguity. The file must have reflink disabled or be allocated with special parameters. On some distros, 'falloc' with --length plus 'xfs_io -c \"reflink disable\"' is required.",
      "examTip": "Alternatively, you can create a dedicated swap partition or use a file system that handles swap files more gracefully, such as ext4."
    },
    {
      "id": 44,
      "question": "A shell script is intended to read from standard input if no arguments are given, or read from file arguments if provided. Randomly, it reads from the wrong source. Which subtle detail in the script might cause misrouting of stdin?",
      "options": [
        "A while loop reads from /dev/stdin, ignoring subsequent test for $1 and $2.",
        "The script is invoked with a function that redefines $@ in a subshell, losing the argument references.",
        "The script uses 'read line' in a function that is overshadowed by an alias named 'read.'",
        "Bash’s built-in 'test -z' fails if multiple arguments are passed, skipping the if-else block for file input."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Reading from /dev/stdin unconditionally inside a while loop can conflict with the logic to handle file arguments. The script might consume stdin even if files are specified, leading to inconsistent behavior.",
      "examTip": "Use conditional constructs carefully, e.g. `if [ $# -eq 0 ]; then ... else ... fi`, ensuring you don’t preemptively read from stdin."
    },
    {
      "id": 45,
      "question": "A developer tries to systemctl enable a service that depends on /mnt/data. Even though /mnt/data is listed in /etc/fstab, systemd complains about the dependency not being met at boot. Which advanced solution addresses this?",
      "options": [
        "Add After=local-fs.target to the service unit, ensuring local file systems are mounted first.",
        "Use a cron job @reboot to start the service, bypassing systemd’s dependency checks.",
        "Rename /mnt/data to /srv/data, so systemd automatically recognizes it as a data mount.",
        "Mark the service as Type=mount in the unit file, forcing systemd to mount it automatically."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If a service requires a mounted filesystem, add 'After=local-fs.target' (and possibly 'Wants=mnt-data.mount') so systemd starts it only after the local file system is mounted. Without it, systemd might start the service too early.",
      "examTip": "For non-system mount points, create a unit .mount file or specify 'RequiresMountsFor=/mnt/data' in the service."
    },
    {
      "id": 46,
      "question": "A newly compiled kernel module cannot find its dependent symbols, resulting in 'Unknown symbol in module' errors. The module directory has the correct .ko files for all dependencies. Which micro-level nuance is the cause?",
      "options": [
        "The module’s Kbuild file is missing a 'EXPORT_SYMBOL()' directive for those symbols.",
        "The kernel was compiled with CONFIG_MODVERSIONS disabled, so symbol version checks fail.",
        "The developer forgot to run depmod after installing the modules, so symbol resolution fails at load time.",
        "The distribution’s default initramfs blacklists any out-of-tree modules for security reasons."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Whenever you install new modules that reference each other, run `depmod -a` to rebuild the module dependency maps. Without this, modprobe cannot resolve the unknown symbols across modules.",
      "examTip": "If you manually copy .ko files into /lib/modules/..., always run depmod to ensure a consistent modules.dep."
    },
    {
      "id": 47,
      "question": "An admin wants to enforce that a user’s umask is always 0027. They set umask 0027 in /etc/profile, but some user sessions still have 0022. Which subtle factor might override /etc/profile?",
      "options": [
        "The user’s default shell is zsh, so /etc/profile is ignored unless symlinked to /etc/zprofile.",
        "Systemd-run sessions bypass system profile scripts and rely on ephemeral environment configs.",
        "ssh connections skip /etc/profile unless forced with 'AcceptEnv UMASK' in sshd_config.",
        "Bash interactive login vs. non-login shell initialization sequences can ignore /etc/profile in certain circumstances."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Bash may not source /etc/profile in non-login shells. Some distributions also source /etc/bashrc or user’s .bashrc differently. This subtlety leads to inconsistent umask if shells skip /etc/profile.",
      "examTip": "Include the umask in /etc/bashrc or the user’s shell initialization as well, or ensure a login shell is used."
    },
    {
      "id": 48,
      "question": "Despite enabling jumbo frames (MTU 9000) on both a Linux server and its switch, packet captures reveal only 1500-byte frames. The driver supports jumbo frames. Which near-identical oversight might explain the discrepancy?",
      "options": [
        "IPv6 automatically forces fragmentation at 1500 unless the 'jumbov6' sysctl is enabled.",
        "The switch trunk port uses a VLAN tag, requiring an MTU of 9018 to accommodate overhead.",
        "The NIC’s ring buffer is set to a maximum of 1500, ignoring the OS-level MTU.",
        "ARP requests are never responded to, so the interface falls back to a safe default frame size."
      ],
      "correctAnswerIndex": 1,
      "explanation": "When using VLAN tagging, you need an additional 18 bytes for overhead. If the switch port is only set to 9000, it can’t handle the extra bytes, effectively capping at 1500. Setting it to 9018 is often required.",
      "examTip": "Always account for VLAN or other encapsulation overhead when configuring jumbo frames on network equipment."
    },
    {
      "id": 49,
      "question": "An advanced user modifies the grub.cfg directly to change the default kernel. The user claims the changes revert after running `grub2-mkconfig`. Which fundamental detail explains why?",
      "options": [
        "Direct edits to grub.cfg are overwritten by scripts that generate it from /etc/default/grub and /etc/grub.d.",
        "SELinux labeling in /boot prevents persistent manual changes unless you run restorecon after editing grub.cfg.",
        "grub2-mkconfig reverts to the distribution’s default kernel if no 'boot signature' is found in grub.cfg.",
        "The user forgot to run 'grub2-install' to finalize the changes to the Master Boot Record."
      ],
      "correctAnswerIndex": 0,
      "explanation": "GRUB2 config is dynamically generated from templates in /etc/grub.d and /etc/default/grub. Directly editing grub.cfg is temporary; grub2-mkconfig overwrites it based on these templates.",
      "examTip": "Always update /etc/default/grub or the scripts in /etc/grub.d, then run grub2-mkconfig to generate a new grub.cfg."
    },
    {
      "id": 50,
      "question": "PBQ: You suspect a NIC driver bug is causing random link resets. Order the steps to confirm the issue:\n1. dmesg | grep eth0\n2. lspci -v | grep -A5 Ethernet\n3. ethtool -i eth0\n4. modinfo <driver>",
      "options": [
        "2->3->4->1",
        "3->4->2->1",
        "1->2->4->3",
        "2->3->1->4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "First identify the NIC in lspci (2), then see which driver is in use with ethtool (3), gather driver details with modinfo (4), and finally check dmesg for link reset logs (1). This logical flow clarifies the driver version and relevant errors.",
      "examTip": "ethtool -i reveals the module name. modinfo can show version or known issues. dmesg reveals runtime errors."
    },
    {
      "id": 51,
      "question": "A developer uses `sudo docker run -p 8080:80 myapp` on a system with firewalld. They can’t reach the service externally. Locally, `curl localhost:8080` works. Which subtle detail is likely the root cause?",
      "options": [
        "The firewalld default zone denies incoming connections to port 8080, but localhost is allowed.",
        "Docker has userland proxy disabled, so external connections fail unless NAT rules are manually set.",
        "The container’s EXPOSE directive must match 8080:80 instead of 80:8080 for external connectivity.",
        "Port 8080 is privileged on this distribution, requiring CAP_NET_BIND_SERVICE to open it externally."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the local machine can access it but external clients cannot, likely the firewall is blocking inbound traffic on 8080. The Docker NAT rule is in place, but firewalld doesn’t allow 8080 from outside in the default zone.",
      "examTip": "Use `firewall-cmd --list-all` to confirm open ports. Add port 8080 or the service to the public zone to allow external traffic."
    },
    {
      "id": 52,
      "question": "Two different processes named 'java' show identical CPU usage in top, but 'ps -ef' reveals no difference in arguments. The admin wants to confirm which jar each process loaded. Which micro-level approach might help?",
      "options": [
        "Invoke 'readelf -p .java_args /proc/<pid>/exe' to see jar arguments embedded in the executable.",
        "Use 'strings /proc/<pid>/fd/1' to read the stdout buffer, potentially revealing the jar names.",
        "Examine 'ls -l /proc/<pid>/exe' for a symlink to the jar file location on disk.",
        "Check 'lsof -p <pid>' to see which jar files are opened by that process."
      ],
      "correctAnswerIndex": 3,
      "explanation": "lsof can list all open files for the process, including jar files. The other suggestions are less likely or not standard for seeing Java’s jar usage. Checking /proc/<pid>/fd or lsof is the typical approach.",
      "examTip": "Java processes typically open their jar file as a normal file descriptor, so lsof reveals the jar path."
    },
    {
      "id": 53,
      "question": "A developer wants to simplify container orchestration by using Podman instead of Docker. They try to run 'podman-compose up' but see 'command not found.' Which subtlety clarifies this?",
      "options": [
        "podman-compose is not a default tool in Podman; it’s a separate Python project that must be installed.",
        "The developer must alias docker=podman in ~/.bashrc so 'docker-compose' automatically calls 'podman-compose.'",
        "Red Hat-based systems replaced podman-compose with the built-in 'podman orchestrate' command in version 4.0.",
        "Podman does not support Docker Compose syntax; users must rewrite their files in a different YAML format."
      ],
      "correctAnswerIndex": 0,
      "explanation": "podman-compose is an independent Python utility that mimics Docker Compose for Podman. It isn’t installed by default. The other claims are inaccurate or incomplete.",
      "examTip": "Alternatively, you can use 'docker-compose' with an environment variable to direct it to Podman, but that’s more advanced."
    },
    {
      "id": 54,
      "question": "A user modifies iptables to allow inbound port 80, yet there's a separate rule dropping port 443. They assume SSL traffic is still allowed if HTTP is open. But clients can’t load HTTPS. Which nuance about typical web traffic is correct?",
      "options": [
        "HTTP and HTTPS require distinct inbound ports (80 and 443), so dropping 443 blocks SSL traffic entirely.",
        "TLS 1.3 multiplexes port 80 for SSL encryption if 443 is closed, but a kernel patch is required.",
        "iptables merges port 80 and 443 rules if the same interface is used, effectively ignoring the drop rule on 443.",
        "HTTP/2.0 automatically upgrades from 80 to 443 using ALPN, but the drop rule on 443 triggers an immediate RST."
      ],
      "correctAnswerIndex": 0,
      "explanation": "HTTP typically uses port 80, while HTTPS uses port 443. Blocking 443 means SSL requests can’t connect, no matter if port 80 is open. They do not merge or automatically upgrade if 443 is blocked.",
      "examTip": "Ensure both ports 80 and 443 are allowed if hosting standard web traffic with HTTP and HTTPS."
    },
    {
      "id": 55,
      "question": "PBQ: A security breach prompts rotating SSH host keys. Arrange these steps logically:\n1. Remove old host keys from /etc/ssh\n2. ssh-keygen -A\n3. systemctl reload sshd\n4. Update known_hosts on internal management servers",
      "options": [
        "1->2->3->4",
        "2->1->4->3",
        "4->2->1->3",
        "1->4->2->3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "First remove the old keys (1), then generate new ones (2), reload sshd (3), and finally update known_hosts (4). If you update known_hosts too early, you might create mismatched fingerprints.",
      "examTip": "`ssh-keygen -A` regenerates missing host keys. If you need specific key types or lengths, generate them manually."
    },
    {
      "id": 56,
      "question": "A developer sets up a Linux bridge with multiple tap interfaces for virtualization. Packets are dropped in one direction. Which micro detail in the bridge settings is likely responsible?",
      "options": [
        "Spanning tree protocol (STP) is in blocking state for one interface, dropping egress packets.",
        "The tap interfaces have a lower MTU than the bridge, causing bridging to fail silently.",
        "The system has /proc/sys/net/bridge/bridge-nf-call-iptables set to 1, causing iptables to NAT half the traffic.",
        "ARP requests are directed to the physically-bound interface only, ignoring tap interfaces entirely."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If STP is enabled on the bridge, one interface might be placed in blocking state. Packets from that interface would be dropped in that direction. This bridging nuance is easy to miss.",
      "examTip": "Check `brctl showstp <bridge>` or `bridge link show` to verify port states. Disable STP if it’s not needed or configure it properly."
    },
    {
      "id": 57,
      "question": "A system uses iptables NAT for a local subnet. DNS queries from that subnet randomly fail. tcpdump shows partial DNS responses returning from the upstream DNS but never reaching the client. Which nuance might explain the partial drops?",
      "options": [
        "UDP DNS responses exceed 512 bytes, triggering fragmentation that the NAT gateway discards by default.",
        "The kernel automatically blocks DNS traffic if ephemeral port collisions occur at a rate above net.ipv4.udp_collisions.",
        "The NAT rules do not handle multi-packet DNS queries, so subsequent fragments are misrouted to the default gateway.",
        "Iptables conntrack is timing out on DNS sessions if they last longer than the default 1-second limit for UDP flows."
      ],
      "correctAnswerIndex": 3,
      "explanation": "DNS queries can last more than the minimal UDP conntrack timeout. If the flow times out mid-exchange, the NAT table no longer translates return packets, causing partial or lost responses. This is a subtle timing issue.",
      "examTip": "Adjust net.netfilter.nf_conntrack_udp_timeout or use TCP fallback for large DNS responses."
    },
    {
      "id": 58,
      "question": "A Linux-based router runs VRRP with keepalived. Logs show frequent VIP (virtual IP) reassignments between two nodes, even though both nodes appear healthy. Which micro-level mismatch likely triggers the toggling?",
      "options": [
        "One node has a lower VRRP priority but incorrectly set 'nopreempt', forcing continuous takeover attempts.",
        "Both nodes have the same VRRP 'advert_int' setting, causing conflicting VRRP announcements in the same second.",
        "The net.ipv4.ip_nonlocal_bind sysctl is disabled on the secondary node, refusing the VIP assignment.",
        "The primary node uses an older VRRP protocol version, ignoring 'vrrp_sync_group' configurations from the secondary node."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If 'nopreempt' is incorrectly set on a lower priority node, it may keep seizing the VIP from the higher priority node, causing repeated role flipping. VRRP expects only the highest priority node to preempt unless configured otherwise.",
      "examTip": "Check keepalived.conf for priority and preemption settings. Typically, the higher priority node preempts unless nopreempt is configured."
    },
    {
      "id": 59,
      "question": "A system running systemd suddenly fails to read environment variables defined in /etc/environment for newly spawned services. The file is intact. Which advanced explanation is plausible?",
      "options": [
        "The systemd version no longer parses /etc/environment by default, requiring explicit EnvironmentFile usage.",
        "A bug in pam_systemd.so can skip environment loading if the file is not owned by root:root with 600 permissions.",
        "systemd only reads /etc/environment for user sessions, not for system-level services.",
        "The environment variables conflict with existing systemd service variables, so they are overridden."
      ],
      "correctAnswerIndex": 2,
      "explanation": "systemd does not automatically parse /etc/environment for system-level services. That file is typically read by PAM for user sessions. For system services, environment variables must be set in the unit file or with EnvironmentFile= directives.",
      "examTip": "To set system-level environment variables for a service, create drop-in files in /etc/systemd/system/<service>.d/ or specify them in the unit file."
    },
    {
      "id": 60,
      "question": "A developer wants a container to run with minimal Linux capabilities. They remove all but CAP_SYS_CHROOT. The container can’t write to /proc/sys/vm/swappiness anymore. Why might that happen?",
      "options": [
        "Modifying /proc/sys parameters requires CAP_SYS_RESOURCE, which was removed.",
        "Writing to /proc is always disallowed unless SELinux is disabled or the container uses host PID namespace.",
        "CAP_SYS_ADMIN is mandatory for changing kernel parameters in /proc, overshadowing all other caps.",
        "CAP_SYS_PTRACE is needed to write to /proc entries that handle memory management settings."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Modifying /proc/sys typically requires CAP_SYS_ADMIN, a broad capability. Removing it restricts the container from changing kernel parameters. The others might be partially relevant, but CAP_SYS_ADMIN is the key culprit for sysctl changes.",
      "examTip": "Use a minimal set of capabilities but remember CAP_SYS_ADMIN covers a wide range of operations, including sysctl writes."
    },
    {
      "id": 61,
      "question": "PBQ: You have a system locked at runlevel 3 but want to adopt systemd targets. Match each target on the left with its approximate SysV runlevel on the right:\n1. multi-user.target\n2. graphical.target\n3. rescue.target\n4. emergency.target\n\nA. Runlevel 5\nB. Runlevel 1\nC. Runlevel 2/3\nD. Single-user mode with minimal services",
      "options": [
        "1-D, 2-A, 3-B, 4-C",
        "1-C, 2-A, 3-B, 4-D",
        "1-C, 2-D, 3-B, 4-A",
        "1-B, 2-C, 3-A, 4-D"
      ],
      "correctAnswerIndex": 1,
      "explanation": "multi-user.target ~ runlevels 2/3, graphical.target ~ runlevel 5, rescue.target ~ runlevel 1, and emergency.target ~ an even more minimal single-user environment. So 1-C, 2-A, 3-B, 4-D.",
      "examTip": "For immediate changes: `systemctl isolate <target>`. To persist, use `systemctl set-default <target>`."
    },
    {
      "id": 62,
      "question": "A system with journald logs to persistent storage. The admin notices 10GB of logs remain after vacuuming old entries. Which subtlety about journald might cause leftover usage?",
      "options": [
        "journald keeps 10GB as a baseline ring buffer, ignoring vacuum parameters unless disk usage hits 90%.",
        "Another journald namespace exists for user sessions, which the vacuum command didn't touch.",
        "The vacuum operation only removes archived logs older than a certain threshold, but current logs remain.",
        "journald’s index files are not purged by vacuum, so the actual logs are gone but the index size remains identical."
      ],
      "correctAnswerIndex": 2,
      "explanation": "journald vacuuming typically targets older logs by time or size, but active logs remain. If the admin expected an immediate reduction to zero, they might overlook that the current logs still occupy space.",
      "examTip": "Use `journalctl --vacuum-size=...` or --vacuum-time=..., but remember ongoing logs cannot be removed while in use."
    },
    {
      "id": 63,
      "question": "An admin sets up a BIND DNS server as a caching resolver. Queries work, but occasional repeated queries take the same time as the first. The TTL is set to 300 seconds. Which micro-level cause is plausible?",
      "options": [
        "Negative caching is disabled, forcing the resolver to re-validate even valid domains after each query.",
        "DNSSEC is not configured, so queries are being re-forwarded for signature checks each time.",
        "The server’s local clock drifts, invalidating cached entries before their TTL truly expires.",
        "An ephemeral systemd-resolved config conflicts with BIND, occasionally bypassing BIND's cache."
      ],
      "correctAnswerIndex": 3,
      "explanation": "If systemd-resolved is also active, some queries might bypass BIND caching, going directly to external servers. This leads to inconsistent caching behavior, even if BIND’s TTL is correct. The local stub resolver might route queries unpredictably.",
      "examTip": "Disable systemd-resolved or configure your resolv.conf to point explicitly to the BIND server for consistent caching."
    },
    {
      "id": 64,
      "question": "A developer attempts to load a local Docker image onto a different host with 'docker load'. The target host errors: 'manifest for local-image:latest not found.' The user swears the tarball is correct. Which subtlety is likely the cause?",
      "options": [
        "The image was saved with 'docker save' but includes multi-arch manifests that aren’t recognized by older Docker versions.",
        "The Docker tarball must be named local-image.tar specifically, or 'docker load' won't detect the repository name.",
        "docker load only works on images that are pushed to Docker Hub or a registry, not local tarballs.",
        "The local-image was built with BuildKit, which uses a different layering format incompatible with docker load."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the image includes multi-architecture manifests, older Docker versions might fail to parse the index. The error is subtle, referencing a missing manifest or repo tag. Updating Docker or specifying the correct architecture can fix this.",
      "examTip": "You can specify '--platform' when saving or loading, or upgrade Docker to a version supporting multi-arch manifest lists."
    },
    {
      "id": 65,
      "question": "A newly built LFS (Linux From Scratch) system fails to set a default route via DHCP. The DHCP client logs show a successful lease, but the default route remains empty. Which advanced nuance might be missing?",
      "options": [
        "The kernel's IP autoconfiguration is disabled, ignoring DHCP-based routes.",
        "A script in /etc/dhcp/dhclient-exit-hooks or /usr/libexec/dhcp/ is missing, so routes never apply.",
        "The system has an old GATEWAY entry in /etc/sysconfig/network ignoring DHCP routes.",
        "BusyBox’s built-in DHCP client is used, requiring a separate /etc/default/busybox-net config."
      ],
      "correctAnswerIndex": 1,
      "explanation": "DHCP clients typically rely on hook scripts to set the route. If those scripts are missing (common in a custom LFS environment), the route data from DHCP won’t be applied automatically.",
      "examTip": "Check /sbin/dhclient-script or distribution-specific exit-hook scripts that add default routes upon receiving DHCP info."
    },
    {
      "id": 66,
      "question": "BEST: A user wants to pass environment variables securely to a systemd unit without storing them in plain text. Which approach is BEST for minimal plaintext exposure?",
      "options": [
        "Set the Environment= lines directly in the [Service] section of the .service file with masked permissions.",
        "Use an EnvironmentFile=/etc/sysconfig/securevars, ensuring it’s owned by root with 400 permissions.",
        "Store variables in /run/credentials/system, referencing them via LoadCredential directives in systemd unit.",
        "Load them from /dev/shm at runtime by injecting them with a custom ExecStartPre script."
      ],
      "correctAnswerIndex": 2,
      "explanation": "systemd’s LoadCredential directives let you store secrets in /run/credentials/<unit> where permissions are tightly controlled. It’s safer than standard environment files or direct [Service] lines. Minimal plaintext exposure occurs in the main unit file.",
      "examTip": "This feature, introduced in newer systemd versions, helps keep secrets out of world-readable config files."
    },
    {
      "id": 67,
      "question": "After adding new repos in /etc/apt/sources.list.d, apt-get update fails with 'Signature verification failed'. The keys are imported with apt-key. Which subtle nuance might cause the verification error?",
      "options": [
        "A mismatch between the GPG key’s email ID and the repository’s deb line causes apt to reject the signature.",
        "The apt-key command placed the GPG key in a legacy keyring not recognized by modern Debian-based systems.",
        "The repository’s Release file is signed with a subkey not included in the main GPG public key ring.",
        "A pinned priority for the new repository is set to 50, overshadowing the primary repository signature."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Often, a repository might be signed with a subkey that isn't part of the main key in apt’s keyring. If apt doesn't have that subkey, signature verification fails. It's a subtle GPG trust chain nuance.",
      "examTip": "Check the repository’s official instructions. Sometimes you must import a separate subkey or use the recommended secure key distribution method."
    },
    {
      "id": 68,
      "question": "Two ephemeral Docker containers rely on ephemeral hostnames. A legacy application uses gethostbyname to connect. Connection occasionally fails with 'host not found'. Which advanced detail about Docker’s DNS might explain this?",
      "options": [
        "A container’s etc/hosts is regenerated on each Docker start, occasionally missing ephemeral host entries.",
        "Docker DNS uses a short TTL, and the legacy gethostbyname is caching stale data or not supporting re-resolution.",
        "Docker forcibly sets /etc/resolv.conf to 127.0.0.11, ignoring gethostbyname calls from older glibc versions.",
        "The application must use sethostname(2) for ephemeral containers or it cannot bind ephemeral addresses."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Docker’s internal DNS returns container names with short TTL. If gethostbyname caches the old IP and doesn’t re-query after TTL expiration, occasionally queries fail or return stale addresses. This is subtle with older name resolution libraries.",
      "examTip": "Upgrading to newer getaddrinfo-based calls can handle TTL properly. Or set a stable container name/IP if ephemeral changes are too frequent."
    },
    {
      "id": 69,
      "question": "A newly enabled fstrim.timer fails to run on an encrypted LUKS volume mapped at /dev/mapper/cryptdata. The timer logs no errors. Which overlooked condition is likely preventing TRIM?",
      "options": [
        "No 'allow-discards' option was passed to cryptsetup, disallowing TRIM on LUKS volumes by default.",
        "LUKS volumes require a separate discard pass through parted, ignoring fstrim entirely.",
        "Btrfs is layered on top of LUKS, and btrfs handles TRIM differently with subvolume references.",
        "systemd timers cannot run on encrypted volumes that are not present at boot, requiring manual activation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "By default, LUKS encryption blocks TRIM unless explicitly allowed with the 'discard' or 'allow-discards' flag in cryptsetup. Without that, fstrim on the mapped device does nothing.",
      "examTip": "Allowing discards on encrypted volumes can have security trade-offs, as it can reveal which blocks are unused."
    },
    {
      "id": 70,
      "question": "PBQ: You see random kernel messages about 'hung_task_timeout' for processes performing disk I/O. Arrange these steps to investigate:\n1. Check dmesg for 'hung_task' messages.\n2. Use iotop to see if certain processes monopolize I/O.\n3. Examine SMART data with smartctl.\n4. Look at /proc/sys/kernel/hung_task_timeout_secs.",
      "options": [
        "4->1->2->3",
        "1->4->2->3",
        "2->1->4->3",
        "1->2->3->4"
      ],
      "correctAnswerIndex": 1,
      "explanation": "First see the hung_task messages in dmesg (1), check the kernel parameter controlling the timeout (4), identify heavy I/O usage with iotop (2), then check if hardware is failing via SMART (3).",
      "examTip": "hung_task_timeout_secs defaults to 120 seconds. If tasks frequently exceed this, consider investigating disk performance or hardware."
    },
    {
      "id": 71,
      "question": "A developer is testing an iptables rule that logs dropped packets. The logs appear in journald but not in /var/log/messages. System uses rsyslog. Which subtle detail likely causes the separate journald logs to never reach rsyslog?",
      "options": [
        "The imjournal module in rsyslog is disabled, so journald messages aren’t forwarded to traditional logs.",
        "rsyslog is configured with *.none for the kern facility, ignoring iptables logs which use the kern facility.",
        "journald merges packet logs under the 'audit' facility, which is never forwarded to /var/log/messages.",
        "The system is using minimal logging mode, discarding repetitive iptables messages for performance reasons."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If imjournal is disabled or misconfigured, rsyslog never imports journald messages. iptables logs appear in journald but do not get written to /var/log/messages unless they pass through the correct input module.",
      "examTip": "Enable or configure imjournal in /etc/rsyslog.conf, or use forward rules to get journald logs into the classic syslog pipeline."
    },
    {
      "id": 72,
      "question": "A user tries to automate parted commands in a script with 'yes | parted ...'. The script fails at certain prompts. Which near-identical difference in parted's interactive design might sabotage this approach?",
      "options": [
        "Some parted prompts require 'OK' instead of 'yes', so piping 'yes' is insufficient.",
        "parted uses in-memory i18n strings, ignoring the standard input in certain locales.",
        "parted queries the kernel for confirmation, which cannot be answered from user space if parted locks the device.",
        "parted has multiple confirmation prompts requiring different responses, like 'Yes/No' or 'Ignore/Cancel'."
      ],
      "correctAnswerIndex": 3,
      "explanation": "parted can produce different prompts (Yes/No, Fix/Ignore), so blindly piping 'yes' doesn’t address them all. The script might stall or fail on unexpected prompts.",
      "examTip": "Use parted in non-interactive mode if possible or use parted commands like --script with carefully structured command lines."
    },
    {
      "id": 73,
      "question": "An ephemeral container fails to connect to a MySQL database on startup with 'Connection refused'. Checking 10 seconds later, it succeeds. Which subtle container detail is the root cause?",
      "options": [
        "MySQL is installed in the same container but starts after the application tries to connect.",
        "Docker sets a default DNS re-resolution interval of 15 seconds for ephemeral container names.",
        "The container’s networking stack is not fully initialized before the entrypoint runs the app.",
        "Systemd in the container enforces a multi-user.target delay of 10 seconds for all services."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Sometimes the container’s application starts before the Docker network is ready or before the database container is reachable. This ephemeral race condition is common if no orchestrator-based dependency is used.",
      "examTip": "Use a healthcheck or waiting mechanism to ensure the database container is up before the application tries to connect."
    },
    {
      "id": 74,
      "question": "A developer tries to read kernel logs older than 2 weeks using `journalctl --since '2 weeks ago'`. They only see logs up to 1 week old. The server uses systemd with persistent logging. Which microscopic misconfiguration might limit log retention?",
      "options": [
        "The system has /etc/systemd/journal.conf set to SystemMaxUse=1G, forcibly rotating logs after 1 week.",
        "The system clock was changed to 1 week behind, so older logs appear as 'future' entries and are hidden.",
        "The developer is not in the 'systemd-journal' group, so older logs are masked for security.",
        "The journald indexing file is corrupted, ignoring older entries beyond the last vacuum cycle."
      ],
      "correctAnswerIndex": 0,
      "explanation": "systemd-journald might rotate logs once the configured size limit is hit, typically leading to about 1 week of logs for a busy system. Setting SystemMaxUse is a common reason older logs are pruned.",
      "examTip": "Adjust /etc/systemd/journald.conf or reduce log verbosity to keep logs for a longer period."
    },
    {
      "id": 75,
      "question": "BEST: A user wants extremely fine-grained control over which system calls a container can execute, beyond typical Linux capabilities. Which approach is BEST?",
      "options": [
        "Use SELinux in targeted mode for the container, specifying allowed syscalls in a custom policy.",
        "Implement seccomp filters that whitelist or blacklist specific syscalls at container runtime.",
        "Set the container’s user namespace to rootless, automatically blocking high-level syscalls.",
        "Mount /proc/syscall_filters read-only to disallow changes to syscall usage at runtime."
      ],
      "correctAnswerIndex": 1,
      "explanation": "seccomp is designed for precisely controlling syscalls (whitelist or blacklist). SELinux, capabilities, or user namespaces do not provide the same level of granular syscall filtering. This is the best solution for advanced syscall restrictions.",
      "examTip": "Docker has a --security-opt seccomp=profile.json option. Tools like libseccomp can generate custom profiles."
    },
    {
      "id": 76,
      "question": "A junior admin tries to change the default system target from multi-user.target to rescue.target by editing /usr/lib/systemd/system/default.target. The system boots normally into multi-user. Why?",
      "options": [
        "systemd prioritizes /etc/systemd/system/default.target over /usr/lib/systemd/system/default.target if it exists.",
        "The rescue.target conflicts with multi-user.target, forcing a fallback to the higher-level target.",
        "SELinux contexts on /usr/lib prevent user modifications from taking effect in system-managed directories.",
        "systemctl uses a compiled-in default ignoring local changes to default.target unless run in initrd mode."
      ],
      "correctAnswerIndex": 0,
      "explanation": "By design, systemd’s local overrides in /etc/systemd/system/ take precedence over the vendor-supplied units in /usr/lib/systemd/system. Changing the file in /usr/lib does nothing if there’s an override symlink in /etc/systemd/system.",
      "examTip": "Use `systemctl set-default rescue.target` to properly update the symlink for the default target."
    },
    {
      "id": 77,
      "question": "A Red Hat-based system uses /etc/yum.repos.d/*.repo. The admin placed a new .repo file with the correct baseurl and gpgcheck=1. However, 'yum repolist' doesn’t list the repo. Which advanced explanation might be correct?",
      "options": [
        "The .repo file must be named <repoid>.repo for yum to detect it, ignoring generic filenames.",
        "The new repo’s GPG key is missing from /etc/pki/rpm-gpg, causing the repolist to skip it silently.",
        "Each .repo file requires an enabled=1 line under the repo definition for it to appear in repolist.",
        "Yum merges all .repo files into /etc/yum.conf, ignoring the latest .repo file until a new 'yum clean all' is run."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A newly added .repo definition might have 'enabled=0' or no 'enabled=1' line, causing yum to skip it in repolist. This detail is easily overlooked.",
      "examTip": "Check each repo section in the .repo file for 'enabled=1'. GPG key issues typically result in signature errors, not an invisible repo."
    },
    {
      "id": 78,
      "question": "PBQ: Arrange the steps to investigate a Podman container’s unexpected exit:\n1. podman container inspect <container_id>\n2. journalctl -u podman\n3. podman logs <container_id>\n4. check /var/lib/containers/storage/overlay for ephemeral data issues",
      "options": [
        "1->3->2->4",
        "3->1->4->2",
        "2->1->3->4",
        "1->2->4->3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "First, get container details with 'inspect' (1), then see the container logs (3), review system-level Podman logs in journald (2), and finally check the underlying storage for issues (4).",
      "examTip": "Inspect reveals exit code and environment details; logs show the container’s stdout/stderr. journald might reveal system-level errors or SELinux denials."
    },
    {
      "id": 79,
      "question": "Which advanced factor might cause a Linux bridging firewall to drop all VLAN-tagged traffic, even though normal untagged traffic passes?",
      "options": [
        "The ebtables rules do not account for VLAN tags, so frames with VLAN headers are not recognized by the default chain.",
        "The system’s net.ipv4.vlan_filter sysctl is disabled, ignoring VLAN-tagged frames at the NIC level.",
        "iptables treats VLAN traffic as IP-only, requiring a separate bridging chain for 802.1Q frames.",
        "VLAN bridging in Linux requires a separate vxlan interface to handle layer 2 encapsulation."
      ],
      "correctAnswerIndex": 0,
      "explanation": "ebtables is used for Ethernet bridging firewall rules. If the ebtables rules are not configured to handle VLAN tags, those frames get dropped by default. Standard iptables might not see them properly at layer 2.",
      "examTip": "Use 'ebtables -L' to confirm bridging rules. VLAN frames contain extra headers, requiring ebtables or specialized iptables rules with -m vlan (if supported)."
    },
    {
      "id": 80,
      "question": "A system runs out of available pty devices under heavy SSH usage. Which subtle kernel parameter or config might limit the number of pseudo-terminals?",
      "options": [
        "/proc/sys/fs/pty_max",
        "/etc/systemd/limits.conf with PTY=256",
        "/dev/ptmx capacity set by mknod permissions",
        "/etc/ssh/sshd_config with MaxPTY 128"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The maximum number of pty devices is governed by /proc/sys/kernel/pty/max or a similar parameter. If it’s set too low, heavy SSH usage can exhaust available pty devices.",
      "examTip": "Increase the limit, e.g. `echo 4096 > /proc/sys/kernel/pty/max`. Confirm with `ulimit` and ensuring devpts is properly mounted."
    },
    {
      "id": 81,
      "question": "An admin uses Puppet manifests that define a package resource. The same package is installed in one environment but not in another, even though the code is identical. Which advanced nuance might cause the difference?",
      "options": [
        "Puppet uses environment-specific Hiera data that overrides the package state in certain nodes.",
        "The environment’s naming convention blocks certain package states from applying if the version is pinned.",
        "The admin forgot to run 'puppet compile' in the second environment, so the manifest is partially stale.",
        "Puppet modules require explicit 'include <module>' in each environment’s site.pp, or the package resource is skipped."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Hiera or environment-specific data can override class parameters. If one environment’s Hiera sets 'ensure => absent' for that package, it won’t install there. The same code can yield different results based on environment data layers.",
      "examTip": "Check environment hierarchies and 'puppet lookup' to confirm which data is used in each environment."
    },
    {
      "id": 82,
      "question": "A developer sets up wireguard on Linux but sees no handshake from peers. Peers show an 'endpoint' IP that matches the NAT gateway, not the server’s LAN IP. The server sees no incoming packets. Which subtle NAT detail is relevant?",
      "options": [
        "WireGuard requires explicit DNAT rules on the NAT gateway to forward incoming UDP traffic to the server.",
        "IP masquerading only supports TCP by default, ignoring UDP-based VPN traffic unless 'udp=1' is set in sysctl.",
        "WireGuard reuses the ephemeral port from the NAT gateway, conflicting with typical firewall rules for inbound traffic.",
        "The NAT gateway must route ICMP traffic for wireguard keepalives, or the handshake remains incomplete."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the wireguard server is behind a NAT, an inbound port-forward or DNAT rule is needed for the server to receive handshake packets on the wireguard port. Without it, traffic never reaches the server.",
      "examTip": "WireGuard uses UDP. Ensure the correct port (e.g., 51820) is forwarded at the NAT gateway."
    },
    {
      "id": 83,
      "question": "A container uses Alpine Linux and runs a shell script with '#!/bin/bash'. The script fails with 'command not found: bash.' Which subtle distribution difference is correct?",
      "options": [
        "Alpine Linux uses musl libc, so scripts must specify #!/bin/musl-bash instead of /bin/bash.",
        "By default, Alpine includes dash as /bin/sh, not bash, so bash is not installed or available.",
        "BusyBox in Alpine interprets #!/bin/bash as a single literal token, ignoring the space after #!.",
        "The /bin directory in Alpine is symlinked to /usr/bin, causing relative path confusion for bash scripts."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Alpine uses BusyBox with /bin/sh by default. bash is not installed unless explicitly added. The script fails because /bin/bash doesn’t exist. This is a subtle but common Alpine gotcha.",
      "examTip": "Install bash with `apk add bash` or rewrite scripts for POSIX /bin/sh."
    },
    {
      "id": 84,
      "question": "A developer enabled 'username spaces' in Docker for better security isolation. File ownership in mounted volumes now appears as 'nobody' on the host. Which microscopic concept leads to this confusion?",
      "options": [
        "The container’s user 1000 is mapped to host user 65534, resulting in files owned by 'nobody' from the host perspective.",
        "Docker’s overlay2 driver merges all UIDs into a single overlay UID, displayed as 'nobody' externally.",
        "The host is running NIS, which conflicts with local user space mappings, defaulting to the nobody user.",
        "The developer forgot to disable SELinux in container-selinux, causing label mismatches and forcing 'nobody' ownership."
      ],
      "correctAnswerIndex": 0,
      "explanation": "User namespace remapping reassigns container UIDs to different host UIDs. The container’s root might be mapped to a high host UID, often 65534 (nobody). This leads to confusion when viewing ownership from the host.",
      "examTip": "User namespaces enhance security but complicate file ownership on the host. Use 'ls -n' to see numeric IDs or examine /etc/subuid and /etc/subgid for mappings."
    },
    {
      "id": 85,
      "question": "A developer runs 'chmod 2755' on a directory so newly created files inherit the directory group. Yet some files remain with the user’s primary group instead of the directory group. Which advanced factor breaks the SGID inheritance?",
      "options": [
        "The user is creating files from an NFS client that doesn’t honor local SGID bits by default.",
        "A system-wide UMASK setting of 022 overrides the SGID inheritance, forcing the user’s primary group.",
        "A sticky bit is also set on the directory, negating the SGID effect on file creation.",
        "The directory is on a bind mount that lacks the 'bsdgroups' mount option to enforce SGID."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the directory is accessed via NFS, the NFS server might not enforce the SGID bit behavior. Certain NFS versions or export options can ignore group inheritance on newly created files.",
      "examTip": "Remember, NFS is like that rebellious friend—it often ignores SGID bits, so if your files don't switch groups, blame NFS!"
    },
    {
      "id": 86,
      "question": "An administrator must inspect active network connections established specifically by processes running under the 'dbadmin' user. Which command achieves this precisely?",
      "options": [
        "lsof -i -u dbadmin",
        "netstat -tunap | grep dbadmin",
        "ss -ltnp | grep dbadmin",
        "ps aux | grep dbadmin | netstat -p"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof -i -u dbadmin` specifically targets network connections opened by the user 'dbadmin'. The other commands mix functionalities or rely on less precise user filtering.",
      "examTip": "Use `lsof -iTCP -sTCP:LISTEN` to quickly find processes listening on TCP ports."
    },
    {
      "id": 87,
      "question": "You must create a backup of the bootloader configuration for a GRUB2-based Linux system without regenerating configuration files. Which command meets this requirement?",
      "options": [
        "cp /boot/grub2/grub.cfg /boot/grub2/grub.cfg.bak",
        "grub2-mkconfig -o /boot/grub2/grub.cfg.bak",
        "grub2-install --backup /boot/grub2/grub.cfg.bak",
        "dracut --backup /boot/grub2/grub.cfg.bak"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using `cp` directly copies existing configuration without regenerating it. Other commands recreate or install rather than copying existing configuration.",
      "examTip": "Always backup `/boot` files manually to prevent unwanted configuration overwrites."
    },
    {
      "id": 88,
      "question": "An admin needs to display only the UUID and filesystem type of all block devices. Which command precisely accomplishes this?",
      "options": [
        "lsblk -o UUID,FSTYPE",
        "blkid -s UUID -s TYPE",
        "fdisk -l | grep UUID",
        "parted -l | grep -E 'UUID|FSTYPE'"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`blkid -s UUID -s TYPE` explicitly limits output to UUID and filesystem type. The others either display additional information or require extra filtering.",
      "examTip": "`blkid` is ideal for scripting as it directly extracts specific block device attributes."
    },
    {
      "id": 89,
      "question": "To monitor live changes in SELinux permissions denials continuously, which tool provides direct, real-time visibility?",
      "options": [
        "tail -f /var/log/audit/audit.log | grep AVC",
        "ausearch -m avc -ts recent",
        "journalctl -u auditd -f",
        "auditctl -w /var/log/audit/audit.log -p r"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using `tail -f` provides continuous real-time monitoring specifically of AVC denials. Other options either show historical or generic logs.",
      "examTip": "For real-time SELinux troubleshooting, AVC logs via `tail -f` are highly effective."
    },
    {
      "id": 90,
      "question": "Which command sets a persistent sysctl parameter across reboots without requiring an immediate reboot to apply the changes?",
      "options": [
        "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p",
        "sysctl -w net.ipv4.ip_forward=1",
        "echo 1 > /proc/sys/net/ipv4/ip_forward",
        "modprobe ip_forward persist=1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Appending to `/etc/sysctl.conf` and then using `sysctl -p` makes the change persistent without rebooting. Others are temporary or incorrect.",
      "examTip": "Always confirm persistence by checking `/etc/sysctl.conf`."
    },
    {
      "id": 91,
      "question": "To forcefully terminate a zombie process without rebooting, what precise action must an administrator perform?",
      "options": [
        "Kill its parent process",
        "Kill the zombie PID directly",
        "Send SIGKILL to init",
        "Use `pkill -9 zombie`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Zombie processes can only be cleared by killing their parent process. Direct killing is ineffective since zombies are already dead.",
      "examTip": "Identify zombie parents with `ps auxf` to visualize process relationships."
    },
    {
      "id": 92,
      "question": "Which command precisely retrieves kernel messages related to memory issues immediately after boot?",
      "options": [
        "dmesg | grep -i memory",
        "journalctl -k | grep memory",
        "cat /var/log/messages | grep memory",
        "grep memory /var/log/boot.log"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`journalctl -k` reliably retrieves boot-time kernel messages. `dmesg` may lose messages over time, and log files depend on syslog configuration.",
      "examTip": "Prefer `journalctl` for persistent and structured boot logs."
    },
    {
      "id": 93,
      "question": "To precisely enable kernel crash dumps persistently, which file requires modification?",
      "options": [
        "/etc/kdump.conf",
        "/etc/sysctl.conf",
        "/etc/default/grub",
        "/etc/kernel/crashdump.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Crash dumps are specifically managed via `/etc/kdump.conf`. Other files control related but different aspects.",
      "examTip": "Always verify crash dump paths in `/etc/kdump.conf` after editing."
    },
    {
      "id": 94,
      "question": "For accurately displaying detailed ACL entries of a file, which command is most precise?",
      "options": [
        "getfacl <filename>",
        "ls -l <filename>",
        "stat -c %A <filename>",
        "aclshow <filename>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`getfacl` accurately provides detailed ACL entries. Others display limited file permissions or are non-existent commands.",
      "examTip": "Use `setfacl -m` to modify ACL permissions precisely."
    },
    {
      "id": 95,
      "question": "To precisely configure firewall rules persistently in a CentOS system without immediate reload, what must be edited directly?",
      "options": [
        "/etc/firewalld/zones/public.xml",
        "/etc/sysconfig/iptables",
        "iptables-save > /etc/sysconfig/firewall",
        "firewall-cmd --runtime-to-permanent"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Directly editing `/etc/firewalld/zones/public.xml` persistently sets rules without immediate effect. Other methods apply instantly or improperly.",
      "examTip": "Always verify firewall XML files directly for accurate persistence."
    },
    {
      "id": 96,
      "question": "A Linux administrator must temporarily override a kernel parameter to disable IPv6 forwarding until reboot. Which command correctly performs this task?",
      "options": [
        "sysctl net.ipv6.conf.all.forwarding=0",
        "echo 0 > /proc/sys/net/ipv6/conf/default/forwarding",
        "sysctl -w net.ipv6.conf.all.forwarding=0",
        "sed -i 's/net.ipv6.conf.all.forwarding = 1/net.ipv6.conf.all.forwarding = 0/' /etc/sysctl.conf"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`sysctl -w net.ipv6.conf.all.forwarding=0` immediately overrides the kernel parameter until reboot. `sysctl net.ipv6.conf.all.forwarding=0` is missing the `-w` option, making it ineffective. Writing directly to `/proc/sys/net/.../forwarding` impacts only the default, not all interfaces. Modifying `/etc/sysctl.conf` via `sed` would persist after reboot, contrary to the temporary requirement.",
      "examTip": "Temporary kernel parameter changes use `sysctl -w`; permanent ones involve `/etc/sysctl.conf`."
    },
    {
      "id": 97,
      "question": "A junior engineer mistakenly deleted `/var/log/messages`. The senior admin must immediately recreate it with the same permissions and SELinux context. Which command achieves this accurately?",
      "options": [
        "install -m 0640 -o root -g root /dev/null /var/log/messages && restorecon /var/log/messages",
        "touch /var/log/messages && chmod 0644 /var/log/messages && chown root:root /var/log/messages && restorecon /var/log/messages",
        "cat /dev/null > /var/log/messages && chmod 0640 /var/log/messages && restorecon -v /var/log/messages",
        "cp --preserve=context,mode,ownership /dev/null /var/log/messages"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `install` command precisely recreates the file with explicit permissions (`0640`) and ownership (`root:root`), while `restorecon` correctly restores SELinux context. The `touch` command incorrectly sets permissions (`0644`). Using `cat` then `chmod` misses explicit ownership setting. `cp --preserve` cannot set correct permissions or ownership from `/dev/null`.",
      "examTip": "`install` is superior for explicitly setting permissions and ownership when creating critical files."
    },
    {
      "id": 98,
      "question": "An administrator needs to securely erase sensitive data from `/dev/sdb1` ensuring no data recovery is possible. Which command is the most appropriate?",
      "options": [
        "shred -v -z -n 3 /dev/sdb1",
        "dd if=/dev/urandom of=/dev/sdb1 bs=1M status=progress",
        "wipefs -a -f /dev/sdb1 && dd if=/dev/zero of=/dev/sdb1 bs=1M",
        "blkdiscard -s /dev/sdb1 && dd if=/dev/zero of=/dev/sdb1 bs=1M"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`shred -v -z -n 3 /dev/sdb1` securely overwrites data multiple times (3 passes) and zeros afterward, ensuring no recovery. `dd if=/dev/urandom` overwrites only once and slowly. Using `wipefs` followed by zeroing won't securely overwrite multiple times. `blkdiscard` merely signals SSDs to discard blocks but isn't reliable across all hardware.",
      "examTip": "`shred` is specifically designed for secure data wiping through repeated overwriting."
    },
    {
      "id": 99,
      "question": "A critical service must restart automatically following unexpected termination. Which `systemd` unit directive ensures the service restarts exactly five times within a 10-minute interval?",
      "options": [
        "Restart=on-failure\nStartLimitBurst=5\nStartLimitIntervalSec=600",
        "Restart=always\nRestartSec=120\nStartLimitInterval=600",
        "Restart=on-abort\nRestartSec=120\nStartLimitBurst=5",
        "Restart=on-failure\nRestartSec=120\nStartLimitAction=reboot\nStartLimitBurst=5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`Restart=on-failure` combined with `StartLimitBurst=5` and `StartLimitIntervalSec=600` precisely restricts restarts to five times in ten minutes. `Restart=always` restarts continuously without explicit limit. `Restart=on-abort` misses other failures. Adding `StartLimitAction=reboot` causes unwanted reboots instead of graceful failure handling.",
      "examTip": "Combining `Restart=on-failure` with `StartLimitBurst` effectively manages restart frequency in `systemd`."
    },
    {
      "id": 100,
      "question": "An admin must find files modified exactly 3 days ago in `/home`, excluding symbolic links, and delete them after confirmation. Which command meets these exact requirements?",
      "options": [
        "find /home -type f -mtime 3 -exec rm -i {} \\;",
        "find /home -type f -mtime +3 -exec rm -ri {} \\;",
        "find /home -type f -mtime 3 -print0 | xargs -0 rm -i",
        "find /home -type f ! -type l -mtime 3 -exec rm -I {} \\;"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find /home -type f -mtime 3 -exec rm -i {} \\;` correctly targets regular files modified exactly 3 days ago, prompting confirmation. `-mtime +3` targets older files, not exactly 3 days. Piping via `xargs` is valid but less direct. Using `! -type l` after `-type f` is redundant and misleading; `rm -I` prompts less safely than `-i`.",
      "examTip": "`-mtime 3` is exact; `-mtime +3` finds older. Always confirm deletions explicitly using `-exec rm -i`."
    }
  ]
});
