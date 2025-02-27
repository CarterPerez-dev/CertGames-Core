db.tests.insertOne({
  "category": "CompTIA Linux+ XK0-005",
  "testId": 9,
  "testName": "Practice Test",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A systems administrator is investigating slow read/write performance in a newly configured RAID 5 array used by a database. Each disk passes health checks individually, CPU load is moderate, and there is no sign of memory pressure or network bottlenecks. Which underlying misconfiguration is the MOST likely cause of the performance issue?",
      "options": [
        "The RAID stripe size is misaligned with the filesystem block size, causing excessive read-modify-write cycles.",
        "One of the disks was accidentally set as a spare, reducing the active drive count in the RAID array.",
        "The OS is prioritizing the swap partition over the RAID partition, forcing excessive swapping.",
        "The database transaction logs are mounted as read-only, causing partial write failures."
      ],
      "correctAnswerIndex": 0,
      "explanation": "When RAID 5 stripe size mismatches the filesystem block size or the database’s page size, every small write can trigger a read-modify-write cycle, significantly degrading performance. The other options are plausible in different contexts, but do not align closely with the described symptoms.",
      "examTip": "Use `mdadm --detail` and `cat /proc/mdstat` to check RAID configuration, verifying stripe size alignment with block or page sizes."
    },
    {
      "id": 2,
      "question": "Which command permanently enables the SELinux boolean so that Apache (httpd) can make outbound network connections?",
      "options": [
        "setsebool -n httpd_can_network_connect on",
        "semanage boolean -m httpd_can_network_connect=on",
        "chcon -R -t httpd_can_network_connect /var/www/html",
        "setsebool -P httpd_can_network_connect on"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The `-P` flag in `setsebool -P httpd_can_network_connect on` writes the change to the SELinux policy store, making it persist across reboots. The other commands either alter different attributes or do not persist the change.",
      "examTip": "Use `getsebool -a | grep httpd` to confirm which booleans are set for Apache services."
    },
    {
      "id": 3,
      "question": "A DevOps engineer attempts to pull a private container image from an internal registry but receives an 'authentication required' error. The correct credentials are known. Which command must be run first to resolve this error before pulling the image?",
      "options": [
        "docker push internal.registry.local/myimage:latest",
        "docker login internal.registry.local",
        "docker commit internal.registry.local/myimage:latest",
        "docker save internal.registry.local/myimage:latest > local.tar"
      ],
      "correctAnswerIndex": 1,
      "explanation": "You must authenticate to the internal registry first with `docker login`. Pushing, committing, or saving an image does not address authentication for pulls.",
      "examTip": "For Podman, use `podman login <registry>` instead. Always confirm you are logged in before pulling private images."
    },
    {
      "id": 4,
      "question": "Which of the following methods is BEST for ensuring consistent configuration across multiple Linux servers with minimal manual intervention?",
      "options": [
        "Deploy the same OS image to each server manually and adjust configurations as needed.",
        "Use Ansible playbooks committed to version control to automate configuration management.",
        "Create a cron job on each server to mirror configuration files from a single reference system.",
        "Rely on remote SSH scripts that are executed individually on each server for every update."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using an infrastructure-as-code tool such as Ansible, with playbooks in version control, centralizes and automates configuration changes across multiple servers. Cron mirroring and manual OS images are more error-prone, while remote scripts can lead to configuration drift.",
      "examTip": "Infrastructure-as-code solutions like Ansible, Puppet, or Chef prevent drift and provide version-controlled, repeatable deployments."
    },
    {
      "id": 5,
      "question": "PBQ: A developer needs a shell script that checks if CPU usage exceeds 80%, logs a warning to /var/log/cpu_warn.log, and restarts myapp.service via systemd. Which code snippet correctly accomplishes this?",
      "options": [
        "#!/bin/bash\nCPU=$(mpstat 1 1 | awk '/Average/ {print 100 - $12}')\nif [ $CPU -gt 80 ]\nthen\n  echo \"High CPU usage: $CPU%\" >> /var/log/cpu_warn.log\n  systemctl restart myapp.service\nfi",
        "#!/bin/bash\nCPU=$(top -bn1 | grep 'Cpu(s)' | awk '{print 100 - $8}')\nif [ $CPU -lt 80 ]\nthen\n  echo \"CPU usage is critical at $CPU%\" >> /var/log/cpu_warn.log\n  systemctl stop myapp.service\nfi",
        "#!/bin/bash\nCPU=$(mpstat 1 1 | awk '/Average/ {print $12}')\nif [ $CPU -lt 80 ]\nthen\n  echo \"High CPU usage: $CPU%\" >> /var/log/cpu_warn.log\n  systemctl enable myapp.service\nfi",
        "#!/bin/bash\nCPU=$(top -bn1 | awk '/Cpu/ {print $8}')\nif [ $CPU -gt 80 ]\nthen\n  echo \"High CPU usage: $CPU%\" >> /var/log/cpu_warn.log\n  systemctl disable myapp.service\nfi"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Option 1 correctly calculates CPU usage as `100 - idle` from mpstat, compares it against 80, logs a warning, and restarts the service. All other snippets either compare the CPU value incorrectly or run the wrong systemctl actions.",
      "examTip": "Remember: mpstat's idle percentage is field $12 in the 'Average' row. Subtracting $12 from 100 gives total CPU usage."
    },
    {
      "id": 6,
      "question": "A systems administrator must resize a live ext4 filesystem on a logical volume without unmounting it. Which sequence of commands should be used?",
      "options": [
        "vgextend, lvresize, e2fsck, resize2fs",
        "lvextend, resize2fs, e2fsck",
        "lvextend, resize2fs",
        "pvresize, lvresize, mkfs.ext4, mount"
      ],
      "correctAnswerIndex": 2,
      "explanation": "For ext4 on LVM, the typical approach is to extend the logical volume (lvextend) and then run resize2fs. Modern distributions often allow resizing without unmounting. The other commands are either unnecessary or destructive in this context.",
      "examTip": "Always confirm the filesystem supports online resizing before performing the operation."
    },
    {
      "id": 7,
      "question": "A junior engineer wants to enable SSH access on a server using firewalld. Which command will open the correct service on the default zone permanently?",
      "options": [
        "firewall-cmd --zone=public --service=ssh --add-port=22/tcp",
        "firewall-cmd --add-service=ssh --permanent --zone=public",
        "firewall-cmd --add-port=22 --zone=public",
        "firewall-cmd --reload --permanent ssh"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command `firewall-cmd --add-service=ssh --permanent --zone=public` properly opens the SSH service permanently. After that, a `firewall-cmd --reload` is typically used to apply changes.",
      "examTip": "Use `firewall-cmd --list-all` to verify which services or ports are open in each zone."
    },
    {
      "id": 8,
      "question": "An administrator notices suspicious SSH login attempts to a server. After installing and configuring fail2ban, repeated invalid logins are not being blocked. Which configuration file is MOST likely missing or misconfigured?",
      "options": [
        "/etc/fail2ban/fail2ban.local",
        "/etc/fail2ban/jail.local",
        "/etc/ssh/sshd_config",
        "/etc/pam.d/sshd"
      ],
      "correctAnswerIndex": 1,
      "explanation": "In fail2ban, jail.local configures which jails are active and how they handle repeated offenses. If jail.local is missing or improperly configured, fail2ban won't block repeated attempts.",
      "examTip": "fail2ban uses filters (regex in /etc/fail2ban/filter.d/) and jails defined in /etc/fail2ban/jail.local to correlate logs with banning behavior."
    },
    {
      "id": 9,
      "question": "Which nftables command would add a rule to the 'input' chain to accept incoming HTTP traffic on port 80?",
      "options": [
        "nft add rule ip filter input tcp dport 80 drop",
        "nft add rule ip filter output tcp dport 80 accept",
        "nft add rule ip filter input tcp dport 80 accept",
        "nft insert chain ip filter input tcp dport 80 accept"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The correct syntax is `nft add rule ip filter input tcp dport 80 accept`. The other commands either affect the output chain or drop traffic.",
      "examTip": "Always specify the correct family (ip vs. ip6), table (like filter), and chain when adding rules."
    },
    {
      "id": 10,
      "question": "A team lead wants to build a custom RPM package from source on a Fedora system. Which sequence of commands is MOST appropriate?",
      "options": [
        "dnf install rpm-build && rpmbuild -ta source.tar.gz",
        "rpm -qa source.rpm && rpm -Uvh package.rpm",
        "rpmbuild --install src/ && rpm -bb specfile.spec",
        "rpmbuild -bc specfile.spec && dnf install ./RPMS/x86_64/*.rpm"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Typically, you install the rpm-build package, then run `rpmbuild -ta source.tar.gz`. That command uses the included spec file to build the RPM. The other sequences are either incomplete or not typical for building from a tarball.",
      "examTip": "Remember to have your RPM macros set up in `~/.rpmmacros` for a smooth build process."
    },
    {
      "id": 11,
      "question": "PBQ: Match each systemd unit type on the left with its function on the right:\n1. .service\n2. .target\n3. .mount\n4. .timer\n\nA. Grouping and ordering of services\nB. Mount a filesystem\nC. Schedule a job to run at specified intervals\nD. Start or manage a system service",
      "options": [
        "1-B, 2-D, 3-A, 4-C",
        "1-C, 2-A, 3-D, 4-B",
        "1-D, 2-A, 3-B, 4-C",
        "1-A, 2-C, 3-D, 4-B"
      ],
      "correctAnswerIndex": 2,
      "explanation": ".service units manage services, .target units group dependencies, .mount units mount filesystems, and .timer units schedule jobs. So the correct mapping is 1-D, 2-A, 3-B, 4-C.",
      "examTip": "Use `systemctl list-unit-files` to see all recognized unit types and their states."
    },
    {
      "id": 12,
      "question": "When compiling a kernel module named `foo.ko` from source, which command properly inserts it into a running kernel on a typical Linux distribution?",
      "options": [
        "lsmod foo.ko",
        "modinfo foo.ko",
        "rmmod foo.ko",
        "insmod foo.ko"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The `insmod foo.ko` command directly inserts the module into the kernel. `lsmod` lists modules, `modinfo` shows details, and `rmmod` removes modules.",
      "examTip": "For easier dependency handling, use `modprobe foo` instead of `insmod foo.ko` when possible."
    },
    {
      "id": 13,
      "question": "A developer wants to check real-time network connections and listening sockets on a server. Which command provides similar functionality to `netstat -tulpn` on a modern Linux distribution?",
      "options": [
        "lsof -i",
        "ip -s link show",
        "ss -tulpn",
        "tcpdump -n"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `ss -tulpn` command is the modern replacement for `netstat -tulpn`, displaying TCP/UDP sockets, listening ports, and processes. The other commands serve different purposes.",
      "examTip": "`ss` is part of the iproute2 suite, typically pre-installed on modern Linux distributions."
    },
    {
      "id": 14,
      "question": "An administrator must configure a system to log kernel messages to a remote syslog server. Which configuration file would typically be edited to enable remote logging with rsyslog?",
      "options": [
        "/etc/systemd/journald.conf",
        "/etc/syslog.conf",
        "/etc/rsyslog.conf",
        "/etc/default/rsyslog"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Most modern distributions use /etc/rsyslog.conf (or files in /etc/rsyslog.d/) for remote logging configuration. journald.conf is specific to systemd-journald, and /etc/syslog.conf is used by older syslog daemons.",
      "examTip": "Remember to open the appropriate UDP/TCP port (514) on firewalls for remote syslog traffic."
    },
    {
      "id": 15,
      "question": "BEST: A security analyst wants to ensure that SSH is configured for key-based authentication only. Which configuration change is the BEST solution?",
      "options": [
        "Disable the root account in /etc/passwd.",
        "Set `PermitRootLogin no` in /etc/ssh/sshd_config.",
        "Set `PasswordAuthentication no` in /etc/ssh/sshd_config.",
        "Remove the `sshd` user from /etc/shadow."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Setting `PasswordAuthentication no` in sshd_config effectively enforces key-based authentication. Disabling root login or removing users from /etc/shadow doesn't exclusively ensure key-based auth for SSH.",
      "examTip": "Always restart or reload SSH after changing sshd_config for changes to take effect."
    },
    {
      "id": 16,
      "question": "A server is configured to use IPv6 only. Which command can confirm the default IPv6 route on this server?",
      "options": [
        "route -n",
        "ip -6 route show default",
        "netstat -rn6",
        "ss -6 default"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The command `ip -6 route show default` displays the default IPv6 route. The older route/netstat commands may require specific flags or might not be available in minimal systems.",
      "examTip": "Use `ip -6 addr show` and `ip -6 route show` for IPv6 interface and routing checks."
    },
    {
      "id": 17,
      "question": "PBQ: You have an LVM volume group named 'vgdata' with a logical volume '/dev/vgdata/lvbackup'. You need 100GB more space for backups. Place the steps in the correct order:\n1. pvcreate /dev/sdb\n2. lvextend -L +100G /dev/vgdata/lvbackup\n3. vgextend vgdata /dev/sdb\n4. resize2fs /dev/vgdata/lvbackup",
      "options": [
        "1->3->2->4",
        "3->1->2->4",
        "2->1->3->4",
        "1->2->3->4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "First initialize the new physical disk (pvcreate), then extend the volume group (vgextend), then extend the logical volume (lvextend), and finally resize the filesystem (resize2fs).",
      "examTip": "Ensure the filesystem type supports online resizing (e.g., ext4 or xfs with the right tools)."
    },
    {
      "id": 18,
      "question": "Which command identifies detailed information about the system’s CPU, including vendor and model, on a Linux system?",
      "options": [
        "cat /proc/meminfo",
        "dmidecode --type memory",
        "cat /proc/cpuinfo",
        "lspci -v"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The file /proc/cpuinfo contains detailed information about the CPU (vendor, model, speed). The other commands provide memory or PCI device details or require different options.",
      "examTip": "Use `lscpu` for a formatted summary of CPU data across many Linux distributions."
    },
    {
      "id": 19,
      "question": "You want to allow ephemeral containers to run on your Docker host but do not want them to persist data. Which storage driver or configuration ensures that container data is NOT persisted after container removal?",
      "options": [
        "Configure a named volume in Docker",
        "Use the 'aufs' storage driver",
        "Mount a host path with read-only permissions",
        "Use the 'tmpfs' driver for the container volumes"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Using the tmpfs driver means data is stored in memory; once the container stops, data is lost. Named volumes or host paths can persist data, and aufs is an older union filesystem driver that doesn't guarantee ephemeral storage by default.",
      "examTip": "For ephemeral containers, combine a tmpfs volume with stateless microservices."
    },
    {
      "id": 20,
      "question": "An administrator notices a high number of dropped packets on eth0. Hardware checks pass, and there's minimal CPU load. Which is the MOST likely cause?",
      "options": [
        "The network interface is in promiscuous mode.",
        "There is a mismatch in duplex settings between the switch and the NIC.",
        "QoS settings in /etc/sysctl.conf are capping bandwidth.",
        "ARP table is full, causing dropped packets."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A duplex mismatch commonly causes dropped packets and collisions. While the other issues can occur, a duplex mismatch is the classic reason for high drops despite healthy hardware and normal CPU load.",
      "examTip": "Verify interface speed/duplex with `ethtool eth0` and match it on the switch side."
    },
    {
      "id": 21,
      "question": "A script fails to run with 'Permission denied,' even though its permissions are set to -rwxr--r-- (744). Which scenario MOST likely explains this error?",
      "options": [
        "The script's filesystem mount option is 'noexec'.",
        "The script is being executed by root, which disallows scripts by default.",
        "The script was encoded in UTF-8, not ASCII.",
        "AppArmor is set to enforce read-only mode for scripts in this directory."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Mounting a filesystem with the 'noexec' option prevents scripts from being executed. The permission bits (744) are correct for execution by the owner, so the mount option is the likely culprit.",
      "examTip": "Check /etc/fstab or use `mount | grep noexec` to verify if the partition is mounted noexec."
    },
    {
      "id": 22,
      "question": "BEST: An administrator wants to ensure an NFS share remains mounted after each reboot. Which is the BEST practice to achieve this?",
      "options": [
        "Add the mount command to /etc/rc.local.",
        "Use systemd.automount with a manual systemctl enable command each boot.",
        "Configure the share in /etc/fstab with appropriate NFS options.",
        "Run the mount command once and rely on the kernel to maintain it across reboots."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Placing the NFS share in /etc/fstab is the standard, best practice method for ensuring a persistent mount across reboots. The other approaches are either manual, older, or incomplete solutions.",
      "examTip": "Verify the correct NFS options (e.g., `_netdev`, `nfsvers=4`) in /etc/fstab for reliable mounting."
    },
    {
      "id": 23,
      "question": "A script using 'while read line; do ...' syntax reads input from a file. However, the last line of the file is skipped. Which cause is MOST likely?",
      "options": [
        "The file is encoded in Windows format with \\r\\n line endings.",
        "The file lacks a trailing newline at the end.",
        "The read command is restricted by SELinux policies.",
        "The grep command inside the loop eats the final line."
      ],
      "correctAnswerIndex": 1,
      "explanation": "When a text file lacks a trailing newline, some read loops may skip the last line. The other answers are possible in other contexts but not the typical reason for skipping the final line.",
      "examTip": "Ensure text files end with a newline character for shell read loops to function properly."
    },
    {
      "id": 24,
      "question": "An administrator runs `apt-get update && apt-get upgrade` on Ubuntu and sees a message that the kernel was upgraded. What is typically required for the new kernel to take effect?",
      "options": [
        "No further action is required; the new kernel is already running.",
        "A reboot or kexec call is required to load the new kernel.",
        "Run `depmod -a` to register the new kernel modules.",
        "Delete the old kernel package from /boot to free space."
      ],
      "correctAnswerIndex": 1,
      "explanation": "A new kernel typically requires a reboot or a kexec-based reload to become active. Depmod updates module dependencies, but doesn't load the new kernel for runtime use.",
      "examTip": "Plan kernel updates carefully on production systems, scheduling reboots during maintenance windows."
    },
    {
      "id": 25,
      "question": "PBQ: Drag and drop the correct Git commands to their functions:\n1. Create a new commit with staged changes\n2. Merge changes from a remote repository into local master\n3. Stage modified files\n4. Fetch remote updates and rebase them onto local commits\n\nA. git commit\nB. git pull\nC. git add\nD. git pull --rebase",
      "options": [
        "1-C, 2-A, 3-D, 4-B",
        "1-A, 2-B, 3-C, 4-D",
        "1-A, 2-C, 3-D, 4-B",
        "1-B, 2-A, 3-C, 4-D"
      ],
      "correctAnswerIndex": 1,
      "explanation": "1->git commit, 2->git pull merges remote into local, 3->git add stages files, 4->git pull --rebase fetches updates and applies local commits on top. So it's 1-A, 2-B, 3-C, 4-D.",
      "examTip": "Rebasing keeps a cleaner history but can complicate collaboration if others have already pulled your commits."
    },
    {
      "id": 26,
      "question": "A systems administrator observes that users in the 'developers' group have read/write permissions on a directory but cannot delete files created by other developers. Which permission setting can allow group-wide file deletion without affecting user ownership?",
      "options": [
        "Set the directory's permissions to 777 (rwxrwxrwx).",
        "Use the sticky bit (t) on the directory.",
        "Use SGID on the directory and set group ownership to 'developers'.",
        "Grant ownership of the directory to root and enable ACLs for the group."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Setting the SGID bit on the directory ensures all newly created files inherit the directory’s group, allowing group members to manage each other’s files more cohesively. The sticky bit restricts deletion to owners; 777 is often a security risk, and changing ownership alone doesn’t solve group write issues.",
      "examTip": "Combine SGID with appropriate umask or ACLs to ensure consistent group permissions on shared directories."
    },
    {
      "id": 27,
      "question": "An organization using multiple RHEL servers wants to host a single yum repository internally for OS updates. Which file path is used to store repository configurations locally on RHEL-based systems?",
      "options": [
        "/etc/yum.d",
        "/etc/yum.conf",
        "/etc/yum.repos.d",
        "/var/lib/rpm"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Local repository configuration files on RHEL-based systems are typically placed in /etc/yum.repos.d. The main yum.conf is a global config, and /etc/yum.d is not standard.",
      "examTip": "Ensure the baseurl and gpgcheck settings are correct in .repo files for reliable updates."
    },
    {
      "id": 28,
      "question": "A new containerized microservice needs to persist user-generated content. Which approach is recommended for storing data that must outlive containers?",
      "options": [
        "Use a tmpfs volume configured in the Dockerfile",
        "Map a host directory as a volume",
        "Rely solely on Docker’s overlay filesystem",
        "Store data in environment variables"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Mounting a host directory as a volume (or using named volumes) ensures data persists when containers are destroyed. tmpfs is ephemeral, overlay is ephemeral, and environment variables cannot store extensive user content.",
      "examTip": "Persistent storage is critical for stateful containers. Use volumes or external storage solutions for reliability."
    },
    {
      "id": 29,
      "question": "An administrator needs to schedule a system-wide job to run every Sunday at 3 AM. Which file is typically used for system-wide recurring jobs on a Debian-based system?",
      "options": [
        "/etc/cron.daily/",
        "/etc/cron.d/",
        "/var/spool/cron/",
        "/etc/crontab"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Debian-based systems often place system-wide scheduled tasks in /etc/crontab (or /etc/cron.d/ with specified run times). The /etc/cron.daily/ directory is used for daily tasks without a specific time, and /var/spool/cron is user-specific.",
      "examTip": "Use an explicit schedule in /etc/crontab or create a file under /etc/cron.d with the appropriate time."
    },
    {
      "id": 30,
      "question": "A user complains they receive 'Permission denied' when attempting to create files in /tmp, yet `ls -ld /tmp` shows drwxrwxrwt. What is the MOST likely cause?",
      "options": [
        "SELinux context on /tmp is mislabeled, preventing writes.",
        "The user does not have the sticky bit set on their account.",
        "The user is not in the 'tmpuser' group.",
        "A background process removed all write permissions on /tmp."
      ],
      "correctAnswerIndex": 0,
      "explanation": "With correct permissions (drwxrwxrwt), the next suspect is SELinux. A mislabeling of the /tmp context can prevent writes. Checking with `ls -Z /tmp` or `restorecon -R /tmp` can fix the issue.",
      "examTip": "Always verify both traditional Unix permissions and SELinux/AppArmor contexts when troubleshooting access issues."
    },
    {
      "id": 31,
      "question": "An administrator wants to retrieve the IP addresses for 'example.com' using a built-in tool on a CentOS machine. Which command is the simplest approach?",
      "options": [
        "whois example.com",
        "host example.com",
        "nslookup -type=AAAA example.com",
        "ip link show example.com"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using the `host example.com` command returns the domain's A (and possibly AAAA) records. The whois command provides registration data, nslookup can do it but host is simpler, and ip link show is for network interfaces.",
      "examTip": "In some distributions, `nslookup`, `dig`, and `host` might be in separate packages (bind-utils)."
    },
    {
      "id": 32,
      "question": "BEST: A server’s disk usage is at 95% and growing. Which is the BEST first step to investigate large files and directories?",
      "options": [
        "Run `ls -laR /` to list all files recursively.",
        "Use `du -sh /` at the root directory, then drill down further.",
        "Delete /var/log/messages to immediately free space.",
        "Ask users to remove all archived files from home directories."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The du (disk usage) command is the standard approach to identify the largest directories. Listing all files with ls -laR is inefficient, and deleting logs or user files blindly is risky without analysis.",
      "examTip": "Combine `du -sh` with `sort -h` to find the biggest directories quickly."
    },
    {
      "id": 33,
      "question": "An admin runs `df -h` and sees a 1GB partition mounted at /boot at 100% usage. However, only a few kernel images are installed. Which hidden file type might be consuming space?",
      "options": [
        "Named pipes in /boot",
        "Lost or unlinked files held open by processes",
        "Symbolic links in /boot",
        "Sparse files in the initrd"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Even if files are deleted, if a process is still holding them open, the space isn't freed. These are 'lost' in the filesystem but still consume disk space until the process closes them.",
      "examTip": "Use `lsof +L1` to find open but unlinked files."
    },
    {
      "id": 34,
      "question": "A developer is diagnosing an iptables rule that drops connections. They want to see a live count of matches on each rule. Which command will help them watch rule counters in real time?",
      "options": [
        "watch iptables -nvL",
        "iptables-save | grep DROP",
        "iptables -S -w",
        "tail -f /var/log/syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`watch iptables -nvL` refreshes the iptables rules and counters every 2 seconds, showing packet counts. The other commands are either static snapshots or logs, not a live rule counter view.",
      "examTip": "You can specify intervals with watch, e.g., `watch -n 1 iptables -nvL` for every 1 second."
    },
    {
      "id": 35,
      "question": "BEST: An administrator must ensure that a Btrfs subvolume dedicated to container images does not exceed 20GB. Which built-in Btrfs feature is BEST suited for this requirement?",
      "options": [
        "LVM snapshots on the Btrfs partition",
        "Compression with Btrfs mount options",
        "Btrfs subvolume quotas",
        "Traditional disk quotas set via edquota"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Btrfs supports subvolume quotas natively, allowing an admin to set a maximum size on a specific subvolume. LVM snapshots or mount-time compression do not directly limit usage, and edquota is for classical UNIX quotas on standard filesystems.",
      "examTip": "Use `btrfs qgroup` commands to enable and manage Btrfs quotas for subvolumes."
    },
    {
      "id": 36,
      "question": "A server fails to boot. The administrator inspects the GRUB2 configuration and sees a reference to 'initrd.img'. What is the main function of initrd in the Linux boot process?",
      "options": [
        "It contains the main kernel drivers needed to mount the real root filesystem.",
        "It is the BIOS or UEFI firmware, providing initial boot instructions.",
        "It contains system logs to debug the boot process.",
        "It is the user interface for single-user mode."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The initrd (initial ramdisk) includes essential drivers/modules needed to access the root filesystem before pivoting to it. The other options describe different components.",
      "examTip": "mkinitrd or dracut can generate initrd images on many distributions."
    },
    {
      "id": 37,
      "question": "Which Git command do you use to switch to a new feature branch called 'feature-login' derived from the current branch?",
      "options": [
        "git checkout -b feature-login",
        "git branch -f feature-login",
        "git switch feature-login --track",
        "git clone -b feature-login ."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using `git checkout -b feature-login` creates and switches to a new branch called feature-login from the current HEAD. The other commands either force-branch or only switch if the branch already exists.",
      "examTip": "Recent Git versions also allow `git switch -c feature-login` as an alternative."
    },
    {
      "id": 38,
      "question": "When analyzing 'zombie' processes, which Linux process state indicates a zombie in the output of ps or top?",
      "options": [
        "Z",
        "S",
        "D",
        "X"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Z is the process state indicating a zombie process. S typically indicates interruptible sleep, D indicates uninterruptible sleep, and X is a dead process (rarely seen).",
      "examTip": "Zombies are processes that have ended but still retain a process table entry because their parent hasn't reaped them."
    },
    {
      "id": 39,
      "question": "An administrator sets up an automated script that uses SSH key-based authentication to connect to remote servers. Which file typically stores the public key on the remote host for this setup?",
      "options": [
        "~/.ssh/authorized_keys",
        "~/.ssh/id_rsa",
        "/etc/ssh/ssh_config",
        "~/.ssh/known_hosts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "For key-based authentication, the public key is placed in ~/.ssh/authorized_keys on the remote host. The private key remains on the client side. known_hosts tracks host keys, not user keys.",
      "examTip": "Use `ssh-copy-id user@hostname` to simplify copying the public key to the remote host."
    },
    {
      "id": 40,
      "question": "A container is running but is unreachable on port 8080 from external clients. The container was started with `docker run -d mycontainer`. Which additional flag is required to expose port 8080 on the host?",
      "options": [
        "--expose 8080",
        "-p 8080:8080",
        "--link 8080:host",
        "--network=host"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using `-p 8080:8080` publishes port 8080 from the container to the host. `--expose 8080` only informs Docker of the port but doesn’t publish it externally.",
      "examTip": "Always confirm the correct port mapping: container_port:host_port is -p host_port:container_port for Docker."
    },
    {
      "id": 41,
      "question": "An admin wants to ensure logs are retained for at least 90 days. However, /var/log is on a small partition. Which solution addresses log retention without risking partition overfill?",
      "options": [
        "Enable journald forwarding to /dev/null once logs exceed 90 days.",
        "Configure rsyslog to compress and archive logs to a remote syslog server or external storage.",
        "Disable all non-essential logging services in /etc/rsyslog.conf.",
        "Use the 'sync' mount option to ensure log writes are immediately flushed."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Archiving or forwarding logs to remote or external storage is the best approach to ensure retention without local partition overfill. Disabling logs or writing them to /dev/null defeats the retention goal.",
      "examTip": "Log management often involves compression and remote storage for historical data."
    },
    {
      "id": 42,
      "question": "PBQ: You have a Linux server experiencing a kernel panic on boot. Match the following steps in the order to diagnose and possibly fix:\n1. Boot into rescue or single-user mode\n2. Check /var/log/messages or journald logs\n3. Update or rebuild initrd\n4. Inspect recent kernel updates in grub2.cfg",
      "options": [
        "1->2->4->3",
        "4->2->1->3",
        "2->1->3->4",
        "1->4->2->3"
      ],
      "correctAnswerIndex": 3,
      "explanation": "First, boot into rescue mode (1), then inspect recent kernel changes in grub2.cfg (4), check logs (2), and potentially update or rebuild initrd (3). This logical order addresses possible kernel version mismatch or missing modules.",
      "examTip": "Use tools like `dracut` (on RHEL) or `mkinitrd` to rebuild the initrd. Keep older kernels in GRUB to fall back."
    },
    {
      "id": 43,
      "question": "Direct: Which command displays real-time CPU usage by processes in a dynamic, text-based user interface on Linux?",
      "options": [
        "ps -aux",
        "vmstat 1",
        "htop",
        "free -m"
      ],
      "correctAnswerIndex": 2,
      "explanation": "htop is a dynamic real-time process viewer. ps -aux is static, vmstat is system stats, and free -m shows memory usage but not a dynamic process list.",
      "examTip": "Press F6 in htop to sort by different fields like CPU, MEM, etc."
    },
    {
      "id": 44,
      "question": "While investigating container orchestration, an administrator wants to run a single-node, multi-container environment with minimal overhead. Which tool is specifically designed for defining multi-container Docker applications in a single host environment?",
      "options": [
        "Kubernetes",
        "Docker Compose",
        "Terraform",
        "Helm"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Docker Compose is specifically designed for single-node, multi-container environments. Kubernetes and Helm are more complex cluster/orchestration solutions, and Terraform is an infrastructure-as-code tool not limited to containers.",
      "examTip": "Compose uses a YAML file (docker-compose.yml) to define services, networks, and volumes."
    },
    {
      "id": 45,
      "question": "An engineer sees that a server’s load average is constantly above 10, but top shows minimal CPU usage. Which metric in top/htop indicates that processes might be waiting on disk I/O?",
      "options": [
        "IOwait",
        "Memory usage",
        "st CPU time",
        "Nice value"
      ],
      "correctAnswerIndex": 0,
      "explanation": "IOwait is the metric representing time waiting for disk I/O. High IOwait with minimal CPU usage often indicates a storage bottleneck.",
      "examTip": "Use iostat or iotop for deeper analysis of per-disk or per-process I/O wait."
    },
    {
      "id": 46,
      "question": "An admin wants to initialize a new Git repository in an existing project directory. Which command accomplishes this?",
      "options": [
        "git commit -m 'init'",
        "git init",
        "git clone <repo-url>",
        "git add ."
      ],
      "correctAnswerIndex": 1,
      "explanation": "`git init` creates a new repository in the current directory. The other commands either commit changes, clone an external repo, or stage files after initialization.",
      "examTip": "After `git init`, remember to add files and commit the initial version."
    },
    {
      "id": 47,
      "question": "BEST: A security policy mandates that a root-owned script must be executed by an ordinary user, but the script must run with root privileges. Which approach is BEST?",
      "options": [
        "Set the SUID bit on the script file so it always runs as root.",
        "Use visudo to grant the user permission to run the script via sudo.",
        "Store the script in /usr/local/bin and grant 777 permissions.",
        "Change the script’s group ownership to the user’s group."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using sudo with visudo to specifically allow a user to run the root-owned script is safer. Setting the SUID bit on scripts can be a security risk, and changing permissions to 777 or group ownership is not best practice.",
      "examTip": "SUID on scripts is often disabled by default on many distributions due to security concerns."
    },
    {
      "id": 48,
      "question": "Which tool can show real-time network usage by process on Linux, including inbound and outbound rates?",
      "options": [
        "nload",
        "iftop",
        "nmon",
        "iptraf-ng"
      ],
      "correctAnswerIndex": 1,
      "explanation": "iftop displays real-time bandwidth usage by host or IP. nload shows total usage, nmon is a broader system monitor, and iptraf-ng is another interactive tool but more focused on connections than process-level usage.",
      "examTip": "iftop needs to be run with sufficient privileges to access packet details."
    },
    {
      "id": 49,
      "question": "A developer wants to run a command inside a running Docker container named 'webapp'. Which command accomplishes this if they want to run 'ls /var/www'?",
      "options": [
        "docker exec webapp ls /var/www",
        "docker run webapp /bin/ls /var/www",
        "docker attach webapp /var/www",
        "docker ps exec webapp ls /var/www"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `docker exec webapp ls /var/www` command runs a command inside a running container. The others either start a new container or incorrectly attach. `docker attach` does not allow specifying a command like that.",
      "examTip": "Use `docker exec -it <container> bash` to get an interactive shell in the container."
    },
    {
      "id": 50,
      "question": "An admin modifies /etc/ssh/sshd_config to disallow root login but sees no change after restarting SSH. Which step is MOST likely missing?",
      "options": [
        "They must reload or restart systemd-journald for changes to apply.",
        "They need to run `ssh-keygen` to regenerate host keys.",
        "They must run `restorecon` to fix SELinux contexts on sshd_config.",
        "They did not remove the '#' comment character before the directive."
      ],
      "correctAnswerIndex": 3,
      "explanation": "A common oversight is leaving the PermitRootLogin directive commented out with a '#'. This results in no actual config change. The other options are plausible in certain contexts but not the typical reason for ignoring the setting.",
      "examTip": "Check `sshd -T` to see the effective SSH configuration. This reveals if a directive is active or still commented."
    },
    {
      "id": 51,
      "question": "A developer wants to selectively run commands if certain environment variables are set, within a shell script. Which statement checks if a variable $ENVVAR is defined and not empty?",
      "options": [
        "if [-e $ENVVAR]; then ...",
        "if [ \"$ENVVAR\" != \"\" ]; then ...",
        "if [ -z $ENVVAR ]; then ...",
        "if [ -s $ENVVAR ]; then ..."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using `[ \"$ENVVAR\" != \"\" ]` checks that the variable is not empty. `-z` checks for zero length, but you'd invert it or check `! -z`. `-e` is for file existence, and `-s` is for file size.",
      "examTip": "Alternatively, use `[ -n \"$ENVVAR\" ]` to test if the variable is non-empty."
    },
    {
      "id": 52,
      "question": "Which RAID level provides both disk mirroring and striping for fault tolerance and performance, often called 'striped mirrors'?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 3,
      "explanation": "RAID 10 (1+0) merges mirroring and striping. RAID 0 is only striping, RAID 1 is mirroring, and RAID 5 includes parity but not full mirroring.",
      "examTip": "RAID 6 is similar to RAID 5 but with double parity, not the same as RAID 10."
    },
    {
      "id": 53,
      "question": "A developer sees \"Permission denied\" when attempting to bind to port 80 in a container running with a non-root user. Which is the simplest solution to allow binding to port 80 without running the container as root?",
      "options": [
        "Use CAP_NET_BIND_SERVICE by adding the capability in Docker run flags.",
        "Change the container’s user to root temporarily.",
        "Modify /etc/services inside the container to allow non-root binding.",
        "Use a custom SELinux policy to allow ephemeral port usage."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Binding to low-numbered ports (<1024) typically requires CAP_NET_BIND_SERVICE. Granting that capability allows non-root processes to bind to privileged ports. Running the container as root is not recommended for security.",
      "examTip": "Use `docker run --cap-add=NET_BIND_SERVICE ...` to enable this specific capability."
    },
    {
      "id": 54,
      "question": "An administrator wants to see if any TCP ports are listening on 10.0.0.5. Which command is the simplest to probe open ports on that host?",
      "options": [
        "nmap 10.0.0.5",
        "curl 10.0.0.5",
        "tcpdump host 10.0.0.5",
        "traceroute 10.0.0.5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "nmap is designed for network exploration and port scanning. curl retrieves data from specific protocols, tcpdump captures packets, and traceroute checks the route, not open ports.",
      "examTip": "Use `nmap -sS` for a stealth SYN scan or `nmap -A` for more detailed info."
    },
    {
      "id": 55,
      "question": "PBQ: You need to compress a directory `/var/data` and preserve permissions, then transfer it to `remotehost` via SSH on port 2222. Arrange the commands in the correct sequence:\n1. tar -czf data.tar.gz /var/data\n2. scp -P 2222 data.tar.gz user@remotehost:/tmp\n3. cd /var/data\n4. tar -xzf data.tar.gz /tmp/data",
      "options": [
        "3->4->1->2",
        "4->3->1->2",
        "3->1->2->4",
        "1->2->3->4"
      ],
      "correctAnswerIndex": 2,
      "explanation": "First change to /var/data if desired (3), then create the compressed tar (1), transfer the file via scp (2), and optionally extract it on remote (4) if needed. Typically, extraction is done on the remote host, not locally afterward.",
      "examTip": "To preserve permissions, use tar with -p or confirm the receiving user can restore them. Also ensure the correct port with `-P` for scp."
    },
    {
      "id": 56,
      "question": "BEST: When configuring an NTP server, which is the BEST practice for ensuring accurate time across a LAN with minimal external reliance?",
      "options": [
        "Only use the hardware clock as a time source and broadcast it.",
        "Use a single external upstream time source and distribute locally.",
        "Configure multiple upstream NTP servers and let the local server cross-verify them.",
        "Synchronize each client individually to an external time source to reduce local load."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Having multiple external NTP sources allows cross-verification and helps the local server serve accurate time to the LAN. A single source introduces single-point-of-failure risk. Broadcasting only hardware clock time is typically less accurate.",
      "examTip": "For reliability, configure at least 3 or 4 upstream NTP servers so that outliers can be detected and discarded."
    },
    {
      "id": 57,
      "question": "An admin is investigating SELinux denials for the 'named' service. Which command helps generate an SELinux policy that allows the denied actions while preserving security context?",
      "options": [
        "seset --audit named_t",
        "restorecon -R /var/named",
        "audit2allow -w -a",
        "chcon -t named_t /var/named"
      ],
      "correctAnswerIndex": 2,
      "explanation": "audit2allow parses SELinux audit logs and can generate a custom policy module to permit the denied actions. restorecon sets default contexts, but doesn't automatically fix new or nonstandard paths.",
      "examTip": "After generating a policy with audit2allow, test carefully before deploying in production."
    },
    {
      "id": 58,
      "question": "A developer wants to ensure that `ls -la` and `ll` produce colorized output. Which file would be best to define this alias system-wide for bash users?",
      "options": [
        "~/.bashrc",
        "/etc/profile",
        "/etc/bashrc",
        "~/.profile"
      ],
      "correctAnswerIndex": 2,
      "explanation": "In many distributions, /etc/bashrc (or /etc/bash.bashrc) is the system-wide file for bash aliases and functions. /etc/profile handles environment variables for login shells but not typically alias expansions for interactive shells.",
      "examTip": "Different distros may vary. On Debian-based, /etc/bash.bashrc is often used for system-wide aliases."
    },
    {
      "id": 59,
      "question": "An application throws 'Out of memory' errors. Which kernel feature forcibly terminates a process to reclaim memory when the system is critically low?",
      "options": [
        "OOM killer",
        "EarlyOOM daemon",
        "tmpfs flush",
        "Swapd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The OOM (Out of Memory) killer is a kernel mechanism that kills processes to free memory under severe conditions. EarlyOOM is a userspace daemon that proactively kills processes, but not the kernel’s internal mechanism.",
      "examTip": "You can influence OOM killer behavior via oom_score_adj, but preventing memory exhaustion is better than reacting to it."
    },
    {
      "id": 60,
      "question": "An engineer uses `ps -ef | grep myapp` and sees multiple entries. They want to find which parent process started them. Which column in `ps -ef` output identifies the parent process?",
      "options": [
        "PPID",
        "PID",
        "CMD",
        "STAT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The PPID (Parent Process ID) column shows the ID of the process that spawned the listed process. PID is the process itself, CMD is the command, and STAT is the process state.",
      "examTip": "Use `pstree -p` to visualize parent-child relationships in a tree format."
    },
    {
      "id": 61,
      "question": "BEST: A Linux kernel was manually compiled with extra debugging. Which is the BEST method to revert to the distribution’s default kernel without risking an unbootable system?",
      "options": [
        "Delete the custom kernel in /boot and run depmod.",
        "Use your package manager (apt/dnf) to reinstall the distro’s kernel package, then update GRUB.",
        "Disable the custom kernel with `systemctl disable vmlinuz-debug`.",
        "Compile a minimal kernel with only essential modules and rename it to the default name."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Reinstalling the distribution’s kernel package via the package manager ensures dependencies and configuration files are correct, preventing an unbootable system. Deleting or overwriting kernels manually is risky.",
      "examTip": "Always keep at least one known-good kernel in GRUB. Don’t remove older kernels until you confirm stability."
    },
    {
      "id": 62,
      "question": "Direct: Which command line utility is used to manage NIC teaming or bonding configurations on Red Hat-based systems?",
      "options": [
        "nmcli",
        "netstat",
        "ifenslave",
        "dracut-config"
      ],
      "correctAnswerIndex": 0,
      "explanation": "On modern Red Hat-based systems, nmcli (part of NetworkManager) handles bonding/teaming configurations. ifenslave was used on older systems, netstat is for connections, and dracut-config is unrelated to NICs.",
      "examTip": "In older setups or minimal environments, bonding might be done via /etc/sysconfig/network-scripts/ifcfg-bond0 or manual ifenslave usage."
    },
    {
      "id": 63,
      "question": "A shell script is failing on lines with a function call. The script uses `#!/bin/sh`. Which shell feature might not be supported if /bin/sh points to dash, causing the script to fail?",
      "options": [
        "Basic for loops",
        "Command substitution with backticks",
        "Double-bracket [[ conditionals ]]",
        "Arithmetic expansion using $(( ))"
      ],
      "correctAnswerIndex": 2,
      "explanation": "dash (a POSIX shell) doesn’t support certain bash-only features like [[ conditionals ]]. Basic for loops, backticks, and arithmetic expansion are still mostly POSIX compatible. The double-bracket syntax is bash-specific.",
      "examTip": "Use `#!/bin/bash` if your script relies on bash-specific features. dash is lightweight but lacks many advanced features."
    },
    {
      "id": 64,
      "question": "In Linux cgroups (control groups), which resource limit can be configured to prevent a single process from dominating CPU time?",
      "options": [
        "cpuset.cpu_exclusive",
        "cpu.shares",
        "memory.limit_in_bytes",
        "blkio.weight"
      ],
      "correctAnswerIndex": 1,
      "explanation": "cpu.shares sets relative CPU allocation for a cgroup. memory.limit_in_bytes restricts RAM usage, blkio.weight affects I/O scheduling, and cpuset.* manipulates CPU affinity, not time slices specifically.",
      "examTip": "You can also enforce absolute CPU quotas with `cpu.cfs_quota_us` if cgroups v1 or cgroups v2 features are used."
    },
    {
      "id": 65,
      "question": "An automation script uses `sed` to replace text in configuration files. Which sed command performs an in-place substitution of 'foo' with 'bar' in myconfig.conf?",
      "options": [
        "sed 's/foo/bar/g' myconfig.conf",
        "sed -n 's/foo/bar/g' myconfig.conf",
        "sed -i 's/foo/bar/g' myconfig.conf",
        "sed --replace foo=bar myconfig.conf"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using `-i` with sed performs an in-place edit. The first command prints to stdout, the second uses silent mode, and `--replace` is not valid sed syntax.",
      "examTip": "Use `-i.bak` to create a backup before editing files in-place with sed."
    },
    {
      "id": 66,
      "question": "BEST: Which method is BEST for securely storing secrets like database credentials in a containerized environment?",
      "options": [
        "Pass the credentials as environment variables in the Dockerfile.",
        "Store them in a Git repository with restricted read permissions.",
        "Inject them at runtime from a secret management tool like Vault or Docker Swarm secrets.",
        "Compile them into the application binary."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Storing secrets in a dedicated management system and injecting them at runtime is the best practice. Hardcoding or storing credentials in environment variables or Git poses security risks.",
      "examTip": "Kubernetes also has a native secrets mechanism, though more secure solutions often involve external vault services."
    },
    {
      "id": 67,
      "question": "An admin runs `chmod u+s /usr/local/bin/script.sh` intending to allow normal users to execute it with root privileges. However, it still executes in user space. What is MOST likely preventing the script from running with SUID privileges?",
      "options": [
        "Scripts cannot inherit the SUID bit by default on most modern Linux distributions.",
        "The script is in a noexec mount.",
        "The script lacks the correct SELinux context.",
        "The script is not owned by root."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Most Linux distributions disable SUID on scripts by default for security reasons, ignoring the setuid bit. Even if owned by root, the kernel typically disallows it. The other reasons could matter, but the default behavior is a strong possibility.",
      "examTip": "Use sudo policies instead of SUID scripts for safer privilege escalation."
    },
    {
      "id": 68,
      "question": "A developer has a container image that is 2GB in size, which is too large. Which Dockerfile instruction can reduce the final image size by combining multiple steps into a single layer?",
      "options": [
        "FROM scratch",
        "RUN apt-get update && apt-get install -y python3 && apt-get clean",
        "EXPOSE 80",
        "ENTRYPOINT [\"/usr/bin/python3\"]"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Combining apt-get update, install, and clean in a single RUN instruction ensures fewer layers, reducing the final image size. The other instructions do not influence layering as effectively.",
      "examTip": "Also consider using a smaller base image or multi-stage builds to minimize container footprint."
    },
    {
      "id": 69,
      "question": "An admin needs to generate an SSL certificate signing request (CSR) for a web server. Which command is appropriate for generating the CSR and private key together?",
      "options": [
        "openssl req -new -x509 -key server.key -out server.crt",
        "openssl genrsa -aes256 -out server.key 2048",
        "openssl rsa -in server.key -out server.key",
        "openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The `openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr` command creates both the private key and the CSR. The other commands create self-signed certs or reformat existing keys.",
      "examTip": "Remember that -nodes means 'no DES encryption' for the private key (unencrypted)."
    },
    {
      "id": 70,
      "question": "BEST: During an audit, a security officer notes that the server's BIOS/UEFI lacks a password. Which is the BEST reason to configure a BIOS/UEFI password on a Linux server?",
      "options": [
        "It prevents kernel panics by limiting hardware changes.",
        "It ensures SELinux remains enabled on the server.",
        "It restricts boot device changes or modifications to firmware settings.",
        "It encrypts the disk at rest in the BIOS/UEFI firmware."
      ],
      "correctAnswerIndex": 2,
      "explanation": "A BIOS/UEFI password helps restrict physical access to firmware settings, preventing unauthorized changes like booting from alternate media or disabling secure boot. It does not encrypt the disk or guarantee SELinux usage.",
      "examTip": "Physical security is part of layered security. Combine UEFI Secure Boot and password protection for best results."
    },
    {
      "id": 71,
      "question": "An automated build pipeline uses the Chef configuration management tool. Which resource definition is responsible for installing or removing packages in Chef recipes?",
      "options": [
        "package",
        "cookbook_file",
        "service",
        "file"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In Chef, the `package` resource is used to install, upgrade, or remove packages. The other resources handle files or services.",
      "examTip": "An example snippet: `package 'nginx' do; action :install; end`."
    },
    {
      "id": 72,
      "question": "You suspect a user in group 'devops' is editing logs in /var/log. The directory's permissions are drwxr-xr-x. Which command can show if there's an ACL granting devops members write access?",
      "options": [
        "ls -ld /var/log",
        "getfacl /var/log",
        "stat /var/log",
        "chown devops:devops /var/log"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Use `getfacl /var/log` to see if an Access Control List is set, granting additional permissions. The other commands won't reveal ACLs beyond standard Unix permissions or ownership.",
      "examTip": "If you see a plus sign (+) in `ls -l` output, it indicates extended ACLs are in use."
    },
    {
      "id": 73,
      "question": "A system using chrony for time sync is drifting. Which file is typically used to configure servers in a chrony-based time synchronization setup?",
      "options": [
        "/etc/chrony.conf",
        "/etc/ntp.conf",
        "/etc/timezone",
        "/var/lib/chrony/drift"
      ],
      "correctAnswerIndex": 0,
      "explanation": "chrony reads its server configurations from /etc/chrony.conf by default. /etc/ntp.conf is used by the older ntpd, /etc/timezone is for local time settings, and /var/lib/chrony/drift stores drift data.",
      "examTip": "Use `chronyc sources` and `chronyc tracking` to check synchronization status with chrony."
    },
    {
      "id": 74,
      "question": "Direct: Which directive in /etc/sudoers allows a user to run any command with sudo without requiring a password?",
      "options": [
        "username ALL=(ALL:ALL) NOPASSWD: ALL",
        "username ALL=NOPASSWD=(ALL:ALL) ALL",
        "NOPASSWD: ALL username",
        "sudoers_nopw: username"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct syntax is `username ALL=(ALL:ALL) NOPASSWD: ALL`. The second option is incorrectly ordered, and the others are not valid sudoers syntax.",
      "examTip": "Use `visudo` to edit /etc/sudoers safely and avoid syntax errors."
    },
    {
      "id": 75,
      "question": "After patching a systemd timer unit, it fails to run at the expected intervals. Which command ensures the changes in the unit file take effect immediately?",
      "options": [
        "systemctl reload timer.target",
        "systemctl daemon-reload",
        "systemctl restart cron",
        "systemctl run <timer>.timer"
      ],
      "correctAnswerIndex": 1,
      "explanation": "After editing a systemd unit file, run `systemctl daemon-reload` to reload the changes into the systemd manager. The other commands either reload cron or a target, which won’t pick up unit file edits.",
      "examTip": "Don’t forget to enable or start the timer if needed, e.g., `systemctl enable <timer>.timer`."
    },
    {
      "id": 76,
      "question": "A developer wants to store container images in a local private registry. After installing Docker Distribution, how can they tag an image so it can be pushed to localhost:5000?",
      "options": [
        "docker tag myimage:latest localhost:5000/myimage:latest",
        "docker rename myimage:latest localhost:5000/myimage:latest",
        "docker rebase myimage:latest --registry=localhost:5000",
        "docker commit myimage:latest localhost:5000/myimage"
      ],
      "correctAnswerIndex": 0,
      "explanation": "To push to a local registry at port 5000, tag the image with that registry location, e.g., `docker tag myimage:latest localhost:5000/myimage:latest`. The other commands don’t properly retag for a registry push.",
      "examTip": "Follow with `docker push localhost:5000/myimage:latest` to upload it to the registry."
    },
    {
      "id": 77,
      "question": "BEST: A system requires that new logins show an informational message before the user can proceed. Which approach is the BEST for displaying a login banner?",
      "options": [
        "Set a MOTD in /etc/motd for all SSH and local sessions.",
        "Use /etc/issue.net for remote SSH sessions and /etc/issue for local TTY sessions.",
        "Append the message to ~/.bashrc for each user on the system.",
        "Set 'Banner /etc/banner' in /etc/ssh/sshd_config and place the message there."
      ],
      "correctAnswerIndex": 3,
      "explanation": "Using the 'Banner' directive in sshd_config for remote logins is the standard approach. For local TTY logins, /etc/issue is used, but if the question references 'login banner' typically for SSH, Banner is best. The motd is shown after authentication, not before.",
      "examTip": "Remember that /etc/issue.net (or /etc/issue) is shown for local TTY logins, while Banner in sshd_config is for SSH connections."
    },
    {
      "id": 78,
      "question": "A user complains that after mounting a USB drive to /mnt/usb, they cannot create files. The mount output shows: `/dev/sdb1 on /mnt/usb type vfat (ro)`. Which is the MOST likely cause?",
      "options": [
        "The vfat filesystem is not supported by Linux, forcing read-only mode.",
        "The user does not have write permissions to the /mnt/usb directory.",
        "The USB device was manually mounted with the 'ro' option.",
        "The vfat partition is corrupted and automatically mounted read-only."
      ],
      "correctAnswerIndex": 2,
      "explanation": "The mount listing explicitly shows the filesystem is mounted read-only (ro). This is often due to specifying -o ro or an fstab entry. While corruption can cause a read-only mount, the 'ro' in mount options indicates it was set intentionally.",
      "examTip": "Remount it writable with: `mount -o remount,rw /mnt/usb` if the filesystem is healthy."
    },
    {
      "id": 79,
      "question": "A developer tries to use a symbolic link that points to /etc/nginx/nginx.conf, but the symlink is broken. They confirm the link file is present. Which command helps identify where the link actually points?",
      "options": [
        "ls -R /etc/nginx/nginx.conf",
        "ls -l symlink-file",
        "ln -sf symlink-file /etc/nginx/nginx.conf",
        "grep '/etc/nginx/nginx.conf' symlink-file"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using `ls -l symlink-file` displays the target of the symlink. The other commands either list recursively, forcibly re-link, or search the file, which doesn’t reveal the symlink path directly.",
      "examTip": "If the target no longer exists or was moved, the symlink becomes broken."
    },
    {
      "id": 80,
      "question": "PBQ: You need to create a parted partition table in GPT format on /dev/sdc, create one partition of 50GB, then format it with ext4. Place these parted commands in the correct sequence:\n1. mklabel gpt\n2. mkpart primary ext4 1MiB 50GiB\n3. quit\n4. select /dev/sdc",
      "options": [
        "2->1->3->4",
        "4->1->2->3",
        "1->2->4->3",
        "4->2->1->3"
      ],
      "correctAnswerIndex": 1,
      "explanation": "You must select the disk first, `select /dev/sdc` (4), then create a GPT label (1), create the partition (2), and finally quit parted (3).",
      "examTip": "After parted, format with `mkfs.ext4 /dev/sdc1` or parted’s mkfs command if supported."
    },
    {
      "id": 81,
      "question": "A user tries to run a Docker image on an SELinux-enabled host and receives a permission denial on writing to a volume. Which SELinux context adjustment might fix this?",
      "options": [
        "chcon -t svirt_sandbox_file_t /host/data",
        "restorecon -R /etc/docker",
        "setenforce 0 for the container",
        "chcon -t docker_rw_t /host/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "For mounting host directories into containers under SELinux, you often need svirt_sandbox_file_t or container_file_t context on the host path. The others are less likely valid or are unwise (like disabling SELinux).",
      "examTip": "Use `:Z` or `:z` volume mount flags in Docker to automatically set correct SELinux context for the mounted directory."
    },
    {
      "id": 82,
      "question": "Which command shows a line-by-line difference between two text files, highlighting what has changed?",
      "options": [
        "comm file1 file2",
        "patch file1 file2",
        "diff -u file1 file2",
        "grep -v file1 file2"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `diff -u file1 file2` command shows a unified diff of the two files. comm compares sorted lines, patch applies diffs, and grep -v filters lines.",
      "examTip": "Use diff with the -u (unified) or -c (context) option for a more readable output."
    },
    {
      "id": 83,
      "question": "BEST: A developer wants to quickly spin up a multi-container environment with a front-end, back-end, and database on a single host. Which is the BEST solution for a single-host setup?",
      "options": [
        "Deploy to a full Kubernetes cluster with multiple nodes.",
        "Use Docker Compose to define and run multiple containers locally.",
        "Write a custom script to run multiple docker run commands in sequence.",
        "Use Terraform to manage the Docker installation and container runs."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Docker Compose is designed exactly for multi-container applications on a single host. A full Kubernetes cluster is more complex, custom scripts are less maintainable, and Terraform can manage infrastructure but is not the simplest solution for local multi-container orchestration.",
      "examTip": "Compose uses YAML to define each service, network, and volume in a single file."
    },
    {
      "id": 84,
      "question": "An administrator runs `journalctl -u myapp.service` and sees no entries. The app logs to syslog instead. Which directive in systemd service files ensures stdout/stderr go to journald?",
      "options": [
        "LogToJournal=yes",
        "StandardOutput=journal",
        "SyslogOutput=on",
        "ExecStart=/usr/bin/journalize"
      ],
      "correctAnswerIndex": 1,
      "explanation": "StandardOutput=journal routes the service’s output to journald. The other directives are not valid systemd options or do not accomplish the same result.",
      "examTip": "You can also use StandardError=journal or other logging targets like syslog or null."
    },
    {
      "id": 85,
      "question": "A user modifies the sudoers file incorrectly, locking out all sudo access. They still have a root shell open in another terminal. Which command corrects the syntax safely?",
      "options": [
        "nano /etc/sudoers && service sudo restart",
        "visudo /etc/sudoers",
        "cp /dev/null /etc/sudoers",
        "chmod 4755 /etc/sudoers"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using `visudo` checks syntax before saving. The other commands either don’t provide syntax checking or risk clearing the file. You typically don’t restart 'sudo' as it’s not a service but a binary.",
      "examTip": "Always use visudo to edit sudoers or files in /etc/sudoers.d/ to avoid syntax errors."
    },
    {
      "id": 86,
      "question": "A container logs to stdout, but the logs are filling the Docker host's disk. Which built-in Docker feature can limit or rotate container logs?",
      "options": [
        "docker logs --max-size",
        "Docker overlay driver",
        "Logging driver options, e.g. --log-opt max-size=10m",
        "Log compression in the Docker Daemon settings"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Docker allows setting a logging driver and using log-opt flags (e.g. max-size, max-file) to rotate logs. The other options are partial or do not exist. The 'overlay driver' is for container storage, not logs.",
      "examTip": "Set your logging driver in /etc/docker/daemon.json or via docker run parameters to avoid giant log files."
    },
    {
      "id": 87,
      "question": "A junior admin typed `iptables -P INPUT DROP` on a remote server, locking out SSH. Which command can quickly restore inbound SSH access if they still have a local console?",
      "options": [
        "iptables -F",
        "iptables -D INPUT DROP",
        "iptables -P INPUT ACCEPT",
        "iptables -X"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Setting the default INPUT policy to ACCEPT (`iptables -P INPUT ACCEPT`) reopens inbound traffic. Flushing (iptables -F) removes rules but doesn’t change the policy. Deleting a DROP rule doesn’t fix the policy, and -X removes user-defined chains.",
      "examTip": "Always be careful setting default policies to DROP remotely. A safe approach is to add an ACCEPT rule for SSH before changing the default policy."
    },
    {
      "id": 88,
      "question": "Which command creates a new local branch called 'fix-bug', based on the remote 'origin/bugfix' branch?",
      "options": [
        "git checkout fix-bug origin/bugfix",
        "git checkout -b fix-bug origin/bugfix",
        "git fetch origin/bugfix",
        "git rebase origin/bugfix fix-bug"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Using `git checkout -b fix-bug origin/bugfix` creates and checks out a new local branch fix-bug tracking origin/bugfix. The other commands do not both create and base the new branch on the remote.",
      "examTip": "You can also use `git switch -c fix-bug origin/bugfix` on newer Git versions."
    },
    {
      "id": 89,
      "question": "An admin wants to compile the latest btrfs-progs from source on a Debian system. Which approach is typical for retrieving necessary library headers before compiling?",
      "options": [
        "apt-get install btrfs-progs",
        "apt-get source btrfs-progs",
        "apt-get build-dep btrfs-progs",
        "dpkg -i btrfs-progs-devel.deb"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`apt-get build-dep btrfs-progs` installs the headers and dependencies needed to build btrfs-progs from source. The other commands do not specifically install the dev dependencies or are partial solutions.",
      "examTip": "If the package name is different, like btrfs-tools, adjust accordingly and run `apt-get build-dep <package>`."
    },
    {
      "id": 90,
      "question": "BEST: A team wants a consistent environment for a Python web application across dev, staging, and production. Which is the BEST approach?",
      "options": [
        "Provide the same virtualenv folder for all environments via NFS.",
        "Create a container image with the required Python packages and deploy it across environments.",
        "Ask each developer to manually install dependencies on their system with pip.",
        "Embed all Python packages in the application’s source tree."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Building a container image with pinned Python dependencies ensures consistency. Manually installing or using a shared virtualenv is prone to mismatch, and embedding packages in source is unwieldy.",
      "examTip": "Use a requirements.txt or Pipfile to define dependencies, then build the image to ensure reproducibility."
    },
    {
      "id": 91,
      "question": "A user modifies /etc/shadow to change the password expiration period, but sees no effect. Which file might override or conflict with those settings?",
      "options": [
        "/etc/login.defs",
        "/etc/passwd",
        "/etc/default/expire",
        "/etc/skel/.profile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/login.defs can define default password aging policies that might override direct changes in /etc/shadow. /etc/passwd does not hold password expiration data, and the others are unrelated defaults.",
      "examTip": "Use `chage -l username` to see the effective aging info for a user."
    },
    {
      "id": 92,
      "question": "PBQ: Arrange the steps for generating an Ansible playbook that installs Apache on hosts in the [web] group:\n1. name: Ensure Apache is installed\n2. hosts: web\n3. - name: Install Apache on web servers\n4. package:\n   name: httpd\n   state: present",
      "options": [
        "3->2->1->4",
        "2->3->1->4",
        "3->1->2->4",
        "1->2->3->4"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A typical Ansible YAML structure is: `- name: <Play name>` (3), `hosts: web` (2), `tasks:` including `- name: Ensure Apache is installed` (1), then the package module (4). The best matching sequence is 3->2->1->4.",
      "examTip": "Don’t forget to begin the playbook with `- hosts: web` or similar. Then define tasks under it."
    },
    {
      "id": 93,
      "question": "A container logs repeatedly show 'Database unreachable at db:5432'. Which network type might be missing or misconfigured if the 'db' container is on a different Docker network?",
      "options": [
        "User-defined bridge network",
        "Host network",
        "Overlay network",
        "macvlan network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A user-defined bridge network is typically used for multi-container Docker setups on a single host. If the containers are not on the same user-defined network, they can’t resolve each other by container name. Host, overlay, or macvlan are less common for basic multi-container setups on a single host.",
      "examTip": "Create a user-defined network `docker network create mynet` and start containers with `--network mynet` to ensure internal DNS resolution."
    },
    {
      "id": 94,
      "question": "An admin sees many processes in 'D' state in top, which indicates uninterruptible sleep. This typically suggests waiting on what type of resource?",
      "options": [
        "CPU scheduling",
        "Memory allocation",
        "Network buffering",
        "Disk I/O"
      ],
      "correctAnswerIndex": 3,
      "explanation": "Processes stuck in the 'D' state are usually waiting on I/O, especially disk. The kernel does not allow them to be interrupted until I/O completes.",
      "examTip": "Check dmesg or iostat for disk errors or performance issues if many processes are in D state."
    },
    {
      "id": 95,
      "question": "A developer attempts to run a script with `./script.sh` but gets 'bad interpreter: No such file or directory'. Which is the MOST likely reason?",
      "options": [
        "The script is missing execute permissions (chmod +x).",
        "The #! line references an interpreter path that does not exist.",
        "The script was encoded in ASCII instead of UTF-8.",
        "The user is not part of the wheel group."
      ],
      "correctAnswerIndex": 1,
      "explanation": "The error typically indicates the shebang (#!) line points to a non-existent interpreter path. Missing execute permissions yield 'Permission denied', not 'No such file or directory'.",
      "examTip": "Check the shebang line with `head -1 script.sh` to ensure the correct path (e.g., #!/usr/bin/bash)."
    },
    {
      "id": 96,
      "question": "BEST: A security-conscious admin wants to enforce strong passwords across all users. Which configuration is BEST suited for this goal?",
      "options": [
        "Set PASS_MIN_LEN 12 in /etc/login.defs.",
        "Force manual password checks by the admin for every user.",
        "Use a PAM module like pam_pwquality or pam_cracklib with strict settings.",
        "Implement a custom shell script that compares passwords to a dictionary."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using a PAM module (pam_pwquality or pam_cracklib) to enforce complexity and length is the best and most standard approach. Relying solely on login.defs or manual checks is less robust, and shell scripts are error-prone.",
      "examTip": "Adjust values in /etc/security/pwquality.conf or equivalent for minimum length, complexity, etc."
    },
    {
      "id": 97,
      "question": "A server’s IPv6 address changed, but name resolution still returns the old address. Which file or configuration is responsible for static name resolution that might need updating?",
      "options": [
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/etc/hosts.allow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "If a static entry in /etc/hosts is pointing to the old IPv6 address, it will override DNS. The others specify how name resolution occurs or DNS servers, but /etc/hosts is the typical culprit for stale entries.",
      "examTip": "Check /etc/hosts first if DNS changes appear not to be taking effect on the local system."
    },
    {
      "id": 98,
      "question": "A user tries to remove a module with `rmmod mymodule` but gets an error 'Module is in use'. Which command might reveal which processes or modules are using it?",
      "options": [
        "modprobe --unused mymodule",
        "lsmod | grep mymodule",
        "systemctl status mymodule",
        "lsattr /lib/modules/mymodule.ko"
      ],
      "correctAnswerIndex": 1,
      "explanation": "lsmod lists loaded modules and the number of references they have. If references > 0, something is using it. The other commands do not show usage references for a kernel module.",
      "examTip": "Use `modprobe -r mymodule` for more advanced dependency resolution. If references remain, remove or stop the dependent processes first."
    },
    {
      "id": 99,
      "question": "BEST: A new security policy requires container images to be scanned for vulnerabilities before production. Which method is BEST to comply with this requirement?",
      "options": [
        "Use the built-in Docker linting tool to detect vulnerabilities.",
        "Scan images manually with grep for known CVE strings.",
        "Implement an automated image scanning tool such as Clair or Trivy in the CI/CD pipeline.",
        "Post a notice that images contain no known vulnerabilities in README.md."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using an automated scanning tool (Clair, Trivy, Anchore, etc.) integrated into the CI/CD pipeline is the standard best practice for container image vulnerability scanning. The other methods are either manual, incomplete, or purely informational.",
      "examTip": "Regular scanning keeps you aware of newly discovered CVEs. Ensure you also update base images frequently."
    },
    {
      "id": 100,
      "question": "A Linux server’s kernel logs show repeated 'EXT4-fs error' messages on /dev/sda1. The server has had multiple unexpected power losses. Which tool is appropriate for checking and repairing the ext4 filesystem on this partition?",
      "options": [
        "fsck.ext4",
        "xfs_repair",
        "btrfsck",
        "e2label"
      ],
      "correctAnswerIndex": 0,
      "explanation": "fsck.ext4 is specifically designed for checking and repairing ext4 filesystems. xfs_repair, btrfsck, and e2label are for different filesystems or tasks.",
      "examTip": "Run fsck on an unmounted filesystem whenever possible to avoid further damage. For root volumes, you may need to boot into rescue mode."
    }
  ]
});
