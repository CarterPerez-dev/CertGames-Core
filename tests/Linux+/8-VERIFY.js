db.tests.insertOne({
  "category": "CompTIA Linux+ XK0-005",
  "testId": 8,
  "testName": "Practice Test #8 (Formidable)",
  "xpPerCorrect": 40,
  "questions": [
    {
      "id": 1,
      "question": "A system administrator needs to modify a systemd service to restart automatically if it crashes but allow manual stops to persist. Which directive should they use in the unit file?",
      "options": [
        "Restart=on-failure",
        "Restart=always",
        "Restart=unless-stopped",
        "RestartSec=5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`Restart=on-failure` ensures the service restarts only if it fails, while allowing manual stops to persist. `Restart=always` restarts the service regardless of how it stops, `Restart=unless-stopped` is not a valid systemd directive, and `RestartSec=5` sets a restart delay but does not determine restart conditions.",
      "examTip": "Use `systemctl daemon-reload` after modifying a service file to apply changes."
    },
    {
      "id": 2,
      "question": "A server’s boot process halts with a `Kernel Panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)`. What is the MOST likely cause?",
      "options": [
        "The initramfs/initrd image is missing or corrupted.",
        "GRUB is misconfigured and pointing to an invalid kernel.",
        "The `/etc/fstab` file contains incorrect mount options.",
        "A recent `sysctl` change disabled required kernel modules."
      ],
      "correctAnswerIndex": 0,
      "explanation": "A missing or corrupted `initramfs/initrd` image prevents the kernel from locating the root filesystem, causing a boot failure. GRUB misconfiguration can prevent booting but would likely produce a different error. `/etc/fstab` is not parsed until later in the boot process, and `sysctl` changes do not directly impact boot-time filesystem mounting.",
      "examTip": "Boot into a live environment and regenerate the initramfs with `dracut -f /boot/initramfs-$(uname -r).img $(uname -r)`."
    },
    {
      "id": 3,
      "question": "**(PBQ)** A system administrator detects suspicious outbound traffic originating from a server. What is the correct sequence of actions to investigate and mitigate the issue?",
      "options": [
        "1) ss -tunap | grep ESTABLISHED 2) lsof -i -nP 3) iptables -A OUTPUT -d <suspicious_ip> -j DROP",
        "1) tcpdump -i eth0 2) systemctl stop networking 3) fail2ban-client ban <IP>",
        "1) who -a 2) killall -9 sshd 3) iptables -A INPUT -p tcp --dport 22 -j DROP",
        "1) netstat -tulnp 2) reboot the server 3) change all user passwords"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) identifying active connections with `ss`, (2) using `lsof` to determine which process is responsible, and (3) blocking the suspicious IP with `iptables`. Other sequences either prematurely stop networking, use extreme measures like rebooting, or fail to diagnose the root cause before mitigation.",
      "examTip": "Use `tcpdump -nn -i eth0 port 80` to capture suspicious HTTP traffic for analysis."
    },
    {
      "id": 4,
      "question": "Which command allows an administrator to determine whether an application is making excessive use of swap memory?",
      "options": [
        "smem -s swap -r",
        "vmstat -s",
        "free -m",
        "ps aux --sort=-%mem"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`smem -s swap -r` sorts processes by swap usage, making it the best tool for diagnosing excessive swap usage. `vmstat` and `free` report overall system memory usage but do not show per-process swap details, and `ps aux` sorts by memory usage but does not isolate swap consumption.",
      "examTip": "Use `grep VmSwap /proc/*/status` to manually check per-process swap usage."
    },
    {
      "id": 5,
      "question": "A Linux system is experiencing high CPU load, but the `top` command does not show any single process consuming excessive CPU. What is the MOST likely cause?",
      "options": [
        "High I/O wait due to disk bottlenecks",
        "A zombie process consuming system resources",
        "A runaway process stuck in an infinite loop",
        "A CPU-bound application running with `nice -19` priority"
      ],
      "correctAnswerIndex": 0,
      "explanation": "High CPU load without a single dominant process often indicates high I/O wait (`wa` in `top`), meaning the system is waiting on disk operations. A zombie process does not consume CPU, a runaway process would show up in `top`, and `nice -19` prioritizes a process but does not hide CPU usage.",
      "examTip": "Use `iostat -x 1 5` to check disk I/O performance when troubleshooting CPU load issues."
    },
    {
      "id": 6,
      "question": "Which command should an administrator use to find all files modified in the last 12 hours under `/var/log`?",
      "options": [
        "find /var/log -type f -mmin -720",
        "ls -lt /var/log | head -n 10",
        "stat /var/log/* | grep Modify",
        "grep -r 'last modified' /var/log"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find /var/log -type f -mmin -720` finds files modified in the last 12 hours (720 minutes). `ls -lt` lists files by modification time but does not filter, `stat` shows timestamps but requires manual inspection, and `grep` does not check file metadata.",
      "examTip": "Use `find /var/log -type f -newermt '12 hours ago'` for a more readable approach."
    },
    {
      "id": 7,
      "question": "A Linux administrator needs to enforce password complexity rules for all users. Which file should they modify?",
      "options": [
        "/etc/security/pwquality.conf",
        "/etc/pam.d/common-password",
        "/etc/login.defs",
        "/etc/passwd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Password complexity policies are set in `/etc/security/pwquality.conf`. `/etc/pam.d/common-password` enforces authentication rules but does not define complexity, `/etc/login.defs` handles aging policies, and `/etc/passwd` stores user data but does not enforce password policies.",
      "examTip": "Use `chage -l <user>` to check a user's password aging and expiration settings."
    },
    {
      "id": 8,
      "question": "A system administrator needs to allow only key-based authentication while disabling password authentication in SSH. Which option should they modify in `/etc/ssh/sshd_config`?",
      "options": [
        "PasswordAuthentication no",
        "ChallengeResponseAuthentication no",
        "PermitRootLogin prohibit-password",
        "UsePAM no"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting `PasswordAuthentication no` ensures that only key-based authentication is allowed. `ChallengeResponseAuthentication no` disables interactive challenge-based authentication, `PermitRootLogin prohibit-password` prevents root login with passwords but not for other users, and `UsePAM no` disables PAM integration but does not enforce key-based authentication.",
      "examTip": "After modifying SSH settings, restart the service using `systemctl restart sshd`."
    },
    {
      "id": 9,
      "question": "A system administrator suspects that a recently installed package introduced vulnerabilities. Which command should they use to verify installed files against the package database?",
      "options": [
        "rpm -Va",
        "yum check-update",
        "dpkg --verify",
        "apt list --installed"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`rpm -Va` verifies installed RPM packages against their checksums and metadata. `yum check-update` checks for available updates but does not verify installed files, `dpkg --verify` is for Debian-based systems, and `apt list --installed` only lists installed packages.",
      "examTip": "Look for 'missing' or 'modified' files in the output of `rpm -Va`."
    },
    {
      "id": 10,
      "question": "A Linux administrator needs to enforce a policy where users can only log in between 8 AM and 6 PM. Which file should they modify?",
      "options": [
        "/etc/security/time.conf",
        "/etc/pam.d/sshd",
        "/etc/login.defs",
        "/etc/default/useradd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/security/time.conf` file defines time-based login restrictions using PAM. `/etc/pam.d/sshd` configures SSH-specific policies, `/etc/login.defs` manages user defaults but does not enforce login times, and `/etc/default/useradd` sets default user creation options.",
      "examTip": "Use `pam_time.so` in PAM configuration to enforce time-based access controls."
    },
    {
      "id": 11,
      "question": "**(PBQ)** A system administrator needs to troubleshoot a failing RAID 1 array. What is the correct sequence of actions?",
      "options": [
        "1) cat /proc/mdstat 2) mdadm --detail /dev/md0 3) mdadm --add /dev/md0 /dev/sdb1",
        "1) fdisk -l 2) mkfs.ext4 /dev/md0 3) reboot",
        "1) systemctl restart mdmonitor 2) lvextend -L +10G /dev/md0 3) resync the array",
        "1) umount /dev/md0 2) reformat /dev/md0 3) re-add missing disks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best troubleshooting sequence is (1) checking RAID status with `/proc/mdstat`, (2) gathering detailed information with `mdadm --detail`, and (3) re-adding failed disks with `mdadm --add`. Other sequences involve unnecessary steps or destructive actions.",
      "examTip": "Use `mdadm --fail /dev/md0 /dev/sdb1` to simulate disk failures in a test environment."
    },
    {
      "id": 12,
      "question": "A Linux administrator needs to configure a persistent alias for a frequently used command. Which file should they modify?",
      "options": [
        "~/.bashrc",
        "/etc/environment",
        "/etc/aliases",
        "/etc/profile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `~/.bashrc` file is used to define user-specific aliases that persist across sessions. `/etc/environment` sets environment variables but not aliases, `/etc/aliases` configures mail aliases, and `/etc/profile` is for system-wide environment settings but does not handle per-user aliases effectively.",
      "examTip": "Use `source ~/.bashrc` to apply changes immediately without logging out."
    },
    {
      "id": 13,
      "question": "Which command should an administrator use to display the NUMA (Non-Uniform Memory Access) topology of a system?",
      "options": [
        "numactl --hardware",
        "lscpu",
        "dmidecode -t memory",
        "cat /proc/meminfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`numactl --hardware` displays NUMA node distribution and available memory per node. `lscpu` lists CPU details but does not show NUMA topology, `dmidecode -t memory` retrieves memory hardware information, and `/proc/meminfo` shows memory statistics but not NUMA details.",
      "examTip": "Use `numastat` to analyze NUMA memory allocation across nodes."
    },
    {
      "id": 14,
      "question": "A Linux administrator needs to enforce a policy that prevents unauthorized USB storage devices from being used. Which method is the MOST effective?",
      "options": [
        "Blacklist USB storage modules in `/etc/modprobe.d/blacklist.conf`",
        "Use `chattr +i` on `/media` to prevent mounting",
        "Modify `/etc/fstab` to prevent USB mounts",
        "Set filesystem permissions to restrict access to `/dev/sdb`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Blacklisting the USB storage module in `/etc/modprobe.d/blacklist.conf` prevents the kernel from loading it, effectively disabling USB storage. Modifying `/etc/fstab` or filesystem permissions can be bypassed, and `chattr +i` on `/media` does not prevent mounting.",
      "examTip": "Use `modprobe -r usb_storage` to unload the USB storage module immediately."
    },
    {
      "id": 15,
      "question": "A system administrator wants to ensure that a script executes every time a specific user logs in. Where should they place the script?",
      "options": [
        "~/.bash_profile",
        "/etc/profile.d/",
        "/etc/systemd/system/",
        "/etc/cron.daily/"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`~/.bash_profile` is executed at user login, making it the best place to execute a user-specific script. `/etc/profile.d/` is for system-wide scripts, `/etc/systemd/system/` is for system services, and `/etc/cron.daily/` schedules recurring jobs but does not execute on login.",
      "examTip": "Use `echo 'script.sh' >> ~/.bash_profile` to add a script to login execution."
    },
    {
      "id": 16,
      "question": "A Linux administrator needs to list all files opened by a specific user in real time. Which command should they use?",
      "options": [
        "lsof -u <username>",
        "ps -U <username>",
        "who -u",
        "auditctl -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof -u <username>` lists all open files belonging to a specific user. `ps -U` shows running processes but not open files, `who -u` lists logged-in users, and `auditctl -l` displays active audit rules but not open files.",
      "examTip": "Use `lsof +D /path/to/directory` to find all open files in a directory."
    },
    {
      "id": 17,
      "question": "A Linux administrator wants to configure auditd to monitor access to the `/etc/shadow` file. Which command should they use?",
      "options": [
        "auditctl -w /etc/shadow -p wa -k shadow_changes",
        "ausearch --file /etc/shadow",
        "auditd --watch /etc/shadow",
        "tail -f /var/log/audit/audit.log | grep shadow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `auditctl -w` command enables auditing for access to `/etc/shadow`. `ausearch` queries past audit logs but does not enable monitoring, `auditd --watch` is incorrect syntax, and `tail -f` views logs in real-time but does not configure auditing.",
      "examTip": "Use `auditctl -l` to list active audit rules."
    },
    {
      "id": 18,
      "question": "A Linux server is experiencing extremely slow disk write speeds. The administrator needs to check if the write cache is enabled on the drive. Which command should they use?",
      "options": [
        "hdparm -W /dev/sda",
        "iostat -dx 1 5",
        "lsblk -o NAME,ROTA",
        "df -h /"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`hdparm -W /dev/sda` checks whether write caching is enabled on the disk. `iostat -dx` provides performance statistics, `lsblk -o NAME,ROTA` shows rotational status but not caching, and `df -h` displays disk usage, not performance data.",
      "examTip": "Enable write caching with `hdparm -W1 /dev/sda` if supported by the drive."
    },
    {
      "id": 19,
      "question": "**(PBQ)** A Linux administrator is troubleshooting a critical application that is frequently being terminated due to an Out of Memory (OOM) condition. What is the correct sequence of actions to diagnose and resolve the issue?",
      "options": [
        "1) dmesg | grep -i 'oom' 2) free -m 3) adjust OOM priority with `oom_score_adj`",
        "1) killall -9 <application> 2) reboot 3) increase swap size",
        "1) echo 3 > /proc/sys/vm/drop_caches 2) vmstat 1 5 3) stop unused services",
        "1) renice -n -10 <PID> 2) pkill -STOP <PID> 3) systemctl restart application"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking kernel logs for OOM events, (2) reviewing memory usage with `free -m`, and (3) adjusting `oom_score_adj` to prevent critical applications from being killed. Other sequences include unnecessary or destructive steps.",
      "examTip": "Use `echo -1000 > /proc/<PID>/oom_score_adj` to protect a critical process from being killed."
    },
    {
      "id": 20,
      "question": "A Linux administrator needs to force the system to reload the Udev rules without rebooting. Which command should they use?",
      "options": [
        "udevadm control --reload-rules",
        "systemctl restart udev",
        "modprobe udev",
        "sync"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`udevadm control --reload-rules` reloads Udev rules without requiring a reboot. `systemctl restart udev` restarts the Udev service but does not apply new rules immediately, `modprobe` manages kernel modules but not Udev, and `sync` flushes filesystem buffers but does not reload rules.",
      "examTip": "Use `udevadm trigger` after reloading rules to apply them immediately."
    },
    {
      "id": 21,
      "question": "Which command should an administrator use to securely erase a disk before decommissioning it?",
      "options": [
        "shred -n 3 -z /dev/sdX",
        "dd if=/dev/zero of=/dev/sdX bs=1M",
        "wipefs -a /dev/sdX",
        "rm -rf /dev/sdX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`shred -n 3 -z /dev/sdX` securely overwrites the disk multiple times to prevent data recovery. `dd` writes zeroes but is not as secure, `wipefs` removes filesystem metadata but does not erase data, and `rm -rf` deletes files but does not wipe the disk.",
      "examTip": "Use `hdparm --security-erase` for built-in drive erasure if supported."
    },
    {
      "id": 22,
      "question": "A system administrator needs to migrate a running Docker container to another host without downtime. Which tool should they use?",
      "options": [
        "CRIU (Checkpoint/Restore in Userspace)",
        "docker commit && docker save",
        "rsync -av /var/lib/docker/containers",
        "docker cp <container_id>:/data /backup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "CRIU allows live migration of running containers by checkpointing and restoring their state. `docker commit && docker save` saves an image but does not migrate live containers, `rsync` copies data but does not preserve runtime state, and `docker cp` only transfers files.",
      "examTip": "Use `docker checkpoint create` to create a container checkpoint for migration."
    },
    {
      "id": 23,
      "question": "A Linux administrator needs to find all files owned by the `mysql` user that have not been accessed in the last 90 days. Which command should they use?",
      "options": [
        "find / -user mysql -atime +90",
        "ls -lt --time=atime | grep mysql",
        "stat /var/lib/mysql | grep Access",
        "du -sh /var/lib/mysql"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find / -user mysql -atime +90` finds files owned by `mysql` that have not been accessed in the last 90 days. `ls -lt --time=atime` lists files by access time but does not filter by age, `stat` checks a single file, and `du` reports disk usage.",
      "examTip": "Use `-mtime` instead of `-atime` to filter by last modification time."
    },
    {
      "id": 24,
      "question": "A system administrator needs to detect unauthorized privilege escalations on a Linux server. Which log file should they check first?",
      "options": [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/messages",
        "/var/log/dmesg"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/var/log/auth.log` records authentication attempts, including sudo usage, making it the best log for detecting privilege escalations. `/var/log/secure` serves the same purpose on RHEL-based systems, `/var/log/messages` contains general logs, and `/var/log/dmesg` records kernel messages.",
      "examTip": "Use `grep 'sudo:' /var/log/auth.log` to filter privilege escalation attempts."
    },
    {
      "id": 25,
      "question": "A Linux administrator needs to ensure that a particular application always runs with high CPU priority. Which command should they use?",
      "options": [
        "nice -n -10 /usr/bin/app",
        "renice -n -10 -p <PID>",
        "chrt -f 99 /usr/bin/app",
        "ionice -c 1 -p <PID>"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`chrt -f 99 /usr/bin/app` sets a real-time priority for the application, ensuring it gets CPU priority. `nice` and `renice` adjust scheduling priority but do not enforce real-time behavior, and `ionice` manages disk priority, not CPU.",
      "examTip": "Use `chrt -p <PID>` to check the real-time priority of an existing process."
    },
    {
      "id": 26,
      "question": "A Linux server running on KVM is experiencing high I/O latency. The administrator suspects that the virtual machine is exhausting its disk bandwidth. Which command should they use to verify this?",
      "options": [
        "iostat -dx 1 10",
        "virt-top",
        "vmstat -d 1 5",
        "df -hT"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`virt-top` provides real-time CPU and disk usage metrics for virtual machines running under KVM. `iostat` provides disk statistics but does not isolate VM-specific I/O, `vmstat` provides general system performance, and `df` reports disk space usage, not performance.",
      "examTip": "Use `virsh domblkstat <vm_name>` to check per-VM disk usage statistics."
    },
    {
      "id": 27,
      "question": "**(PBQ)** A Linux administrator needs to migrate a running container from one host to another without downtime. What is the correct sequence of actions?",
      "options": [
        "1) Checkpoint the container using `criu` 2) Transfer the state file to the new host 3) Restore the container with `podman restore`",
        "1) Stop the container 2) Save it as an image 3) Transfer and restart it on the new host",
        "1) Use `docker commit` 2) Save the image 3) Load it on the new host",
        "1) Run `rsync -av /var/lib/docker/` 2) Restart the service 3) Update firewall rules"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best method is (1) checkpointing the container using `criu`, (2) transferring the saved state, and (3) restoring the container on the new host using `podman restore`. Other methods involve downtime or do not preserve the running state.",
      "examTip": "Use `podman checkpoint --export` to create a transferable container state."
    },
    {
      "id": 28,
      "question": "A Linux administrator needs to configure a system-wide umask value of `027` to ensure secure default file permissions for new files. Which file should they modify?",
      "options": [
        "/etc/profile",
        "/etc/security/limits.conf",
        "/etc/pam.d/common-session",
        "/etc/sudoers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting `umask 027` in `/etc/profile` ensures a system-wide default for new file permissions. `limits.conf` manages resource limits, `pam.d/common-session` is used for authentication settings, and `sudoers` manages privilege escalation.",
      "examTip": "Use `umask` in a user’s `~/.bashrc` for per-user umask settings."
    },
    {
      "id": 29,
      "question": "A Linux administrator needs to restrict SSH access to only allow connections from a specific subnet (`192.168.1.0/24`). Which configuration should they modify?",
      "options": [
        "Edit `/etc/hosts.allow` and add `sshd: 192.168.1.`",
        "Modify `/etc/ssh/sshd_config` and set `AllowUsers *@192.168.1.*`",
        "Use `iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT`",
        "Add `DenyUsers *@!192.168.1.*` in `/etc/ssh/sshd_config`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding `sshd: 192.168.1.` to `/etc/hosts.allow` ensures only this subnet can connect via TCP Wrappers. `sshd_config` settings do not directly support CIDR notation, and firewall rules should supplement but not replace access control.",
      "examTip": "Use `tcpdmatch sshd 192.168.1.10` to test TCP wrapper access rules."
    },
    {
      "id": 30,
      "question": "Which command should an administrator use to display all active TCP connections along with the process IDs using those connections?",
      "options": [
        "ss -tunap",
        "netstat -antp",
        "lsof -i",
        "tcpdump -i eth0"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`netstat -antp` lists all active TCP connections and their associated process IDs. `ss -tunap` provides similar functionality, `lsof -i` lists open network sockets but does not focus on active TCP sessions, and `tcpdump` captures packets but does not display process IDs.",
      "examTip": "Use `ss -tunap | grep ESTABLISHED` to check active TCP sessions."
    },
    {
      "id": 31,
      "question": "A Linux administrator needs to verify if a specific kernel module (`nf_conntrack`) is loaded. Which command should they use?",
      "options": [
        "lsmod | grep nf_conntrack",
        "modinfo nf_conntrack",
        "insmod nf_conntrack",
        "sysctl -a | grep nf_conntrack"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsmod | grep nf_conntrack` checks if a kernel module is currently loaded. `modinfo` provides module details but does not indicate if it is loaded, `insmod` loads a module but does not verify its status, and `sysctl` manages kernel parameters but does not list modules.",
      "examTip": "Use `modprobe -r nf_conntrack` to unload a loaded module."
    },
    {
      "id": 32,
      "question": "A system administrator needs to check the status of a RAID 5 array on a Linux server. Which command should they use?",
      "options": [
        "cat /proc/mdstat",
        "mdadm --detail /dev/md0",
        "lsblk -o NAME,TYPE,FSTYPE",
        "df -hT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`cat /proc/mdstat` provides real-time RAID status, including active arrays and disk failures. `mdadm --detail` offers more detailed information but does not show a quick summary, `lsblk` lists block devices, and `df -hT` displays mounted filesystems but not RAID details.",
      "examTip": "Use `mdadm --fail /dev/md0 /dev/sdb1` to simulate a disk failure for testing."
    },
    {
      "id": 33,
      "question": "A Linux administrator needs to identify which systemd service is responsible for managing network interfaces on a given server. Which command should they use?",
      "options": [
        "systemctl list-unit-files --type=service | grep -i network",
        "nmcli device status",
        "ip link show",
        "journalctl -u networking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-unit-files --type=service | grep -i network` lists all systemd services related to networking. `nmcli device status` shows NetworkManager-managed interfaces, `ip link show` displays interface states but not service management, and `journalctl` retrieves logs but does not list active services.",
      "examTip": "Use `systemctl list-units --type=service | grep network` to see active network services."
    },
    {
      "id": 34,
      "question": "Which command allows an administrator to remove a logical volume (`lv_data`) safely before deleting the volume group?",
      "options": [
        "lvremove /dev/vg01/lv_data",
        "vgremove vg01",
        "pvremove /dev/sdb1",
        "wipefs -a /dev/vg01/lv_data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Before deleting a volume group, `lvremove` must be used to safely remove logical volumes. `vgremove` deletes the volume group but requires all logical volumes to be removed first. `pvremove` removes physical volume metadata but does not handle logical volumes, and `wipefs` erases filesystem metadata but does not remove LVM structures.",
      "examTip": "Use `vgremove vg01` after removing all logical volumes to delete a volume group."
    },
    {
      "id": 35,
      "question": "**(PBQ)** A Linux administrator is investigating high CPU utilization due to excessive system calls. What is the correct sequence of actions?",
      "options": [
        "1) strace -p <PID> 2) lsof -p <PID> 3) renice -n 10 <PID>",
        "1) ps aux --sort=-%cpu 2) kill -9 <PID> 3) reboot",
        "1) vmstat 1 5 2) stop the process 3) restart the service",
        "1) uptime 2) systemctl restart systemd-journald 3) sync"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best troubleshooting sequence is (1) using `strace` to analyze system calls, (2) identifying open files with `lsof`, and (3) adjusting process priority with `renice`. Other sequences involve unnecessary restarts or extreme measures like killing processes.",
      "examTip": "Use `strace -c -p <PID>` to summarize system calls by frequency."
    },
    {
      "id": 36,
      "question": "A system administrator needs to prevent a system from booting into the default target and instead boot directly into single-user mode for maintenance. Which GRUB modification should they make at boot time?",
      "options": [
        "Edit the kernel line and append `single`",
        "Press `Esc` during boot and select `Rescue Mode`",
        "Modify `/etc/default/grub` and set `GRUB_TIMEOUT=0`",
        "Run `grub2-mkconfig -o /boot/grub2/grub.cfg`"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Appending `single` to the kernel line during boot forces the system into single-user mode. Selecting `Rescue Mode` may work but depends on the distribution, modifying `GRUB_TIMEOUT` affects boot delay, and regenerating GRUB config does not directly change the boot mode.",
      "examTip": "Use `systemctl rescue` from a running system to enter single-user mode without rebooting."
    },
    {
      "id": 37,
      "question": "A Linux administrator needs to capture only HTTP traffic on a network interface for analysis. Which command should they use?",
      "options": [
        "tcpdump -i eth0 port 80",
        "tcpdump -A -nn -i eth0",
        "tshark -i eth0 -f 'tcp port 80'",
        "iptraf-ng -i eth0"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tcpdump -i eth0 port 80` filters packets for HTTP traffic on port 80. `tcpdump -A` captures all traffic in ASCII but does not filter, `tshark -f 'tcp port 80'` works but is not the standard CLI tool for quick packet captures, and `iptraf-ng` provides network statistics but not raw packet capture.",
      "examTip": "Use `tcpdump -w http_traffic.pcap port 80` to save HTTP traffic for later analysis."
    },
    {
      "id": 38,
      "question": "A system administrator needs to ensure that the system clock is synchronized with an NTP server and remains accurate even if the network connection is lost. Which service should they use?",
      "options": [
        "chronyd",
        "ntpd",
        "timedatectl",
        "hwclock --systohc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chronyd` is preferred over `ntpd` as it handles intermittent connections better by making gradual clock adjustments. `timedatectl` configures time settings but does not manage synchronization, and `hwclock` syncs between the system clock and hardware clock but does not maintain synchronization with an external server.",
      "examTip": "Use `chronyc tracking` to verify NTP synchronization status."
    },
    {
      "id": 39,
      "question": "A system administrator needs to enable logging of all user commands executed on a server for auditing purposes. Which file should they modify?",
      "options": [
        "/etc/bash.bashrc",
        "/etc/audit/rules.d/audit.rules",
        "/etc/security/limits.conf",
        "/etc/login.defs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Modifying `/etc/audit/rules.d/audit.rules` enables command logging using auditd. `/etc/bash.bashrc` can log user commands but can be bypassed, `/etc/security/limits.conf` controls resource limits, and `/etc/login.defs` sets default user policies but does not log commands.",
      "examTip": "Use `auditctl -a always,exit -F arch=b64 -S execve` to log all executed commands."
    },
    {
      "id": 40,
      "question": "A Linux administrator needs to limit the maximum number of open files for a specific user. Which file should they modify?",
      "options": [
        "/etc/security/limits.conf",
        "/etc/systemd/system.conf",
        "/etc/profile",
        "/etc/default/ulimit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "File limits for users are set in `/etc/security/limits.conf`. `/etc/systemd/system.conf` controls system-wide limits, `/etc/profile` sets environment variables, and `/etc/default/ulimit` is not a standard configuration file.",
      "examTip": "Use `ulimit -n` to check the current maximum number of open files per user."
    },
    {
      "id": 41,
      "question": "A Linux administrator needs to configure a persistent network alias for a specific interface using systemd-networkd. Which file should they modify?",
      "options": [
        "/etc/systemd/network/10-eth0.network",
        "/etc/network/interfaces",
        "/etc/sysconfig/network-scripts/ifcfg-eth0",
        "/etc/resolv.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/systemd/network/10-eth0.network` is used by systemd-networkd to configure network interfaces. `/etc/network/interfaces` is for Debian-based systems using ifupdown, `/etc/sysconfig/network-scripts/ifcfg-eth0` is for RHEL-based distributions using NetworkManager, and `/etc/resolv.conf` is for DNS settings.",
      "examTip": "After modifying systemd-networkd files, apply changes with `systemctl restart systemd-networkd`."
    },
    {
      "id": 42,
      "question": "A Linux administrator wants to set up a firewall rule using `nftables` that drops all incoming traffic except for SSH and HTTP/S. Which command should they use?",
      "options": [
        "nft add rule inet filter input ip daddr 0.0.0.0/0 tcp dport {22, 80, 443} accept; nft add rule inet filter input drop",
        "iptables -A INPUT -p tcp --match multiport --dports 22,80,443 -j ACCEPT",
        "firewall-cmd --add-service=ssh --add-service=http --add-service=https --permanent",
        "ufw allow 22; ufw allow 80; ufw allow 443"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `nftables` rule explicitly allows SSH and HTTP/S while dropping all other incoming traffic. The `iptables` rule works but is not `nftables`, `firewall-cmd` applies only to `firewalld`, and `ufw` is specific to Ubuntu-based systems.",
      "examTip": "Use `nft list ruleset` to verify applied `nftables` rules."
    },
    {
      "id": 43,
      "question": "**(PBQ)** A Linux system is experiencing high swap usage despite having sufficient free RAM. What is the correct sequence of actions to diagnose and resolve the issue?",
      "options": [
        "1) free -m 2) sysctl vm.swappiness=10 3) swapoff -a && swapon -a",
        "1) dmesg | grep swap 2) reboot 3) clear swap cache",
        "1) top -o %MEM 2) echo 3 > /proc/sys/vm/drop_caches 3) stop unused services",
        "1) vmstat 1 5 2) pkill -9 <PID> 3) disable swap permanently"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking swap and RAM usage, (2) reducing the kernel's swappiness to prefer RAM over swap, and (3) refreshing swap allocation by turning it off and back on. Other sequences include unnecessary or destructive steps.",
      "examTip": "Set `vm.swappiness=10` in `/etc/sysctl.conf` to persist changes across reboots."
    },
    {
      "id": 44,
      "question": "A Linux administrator needs to find and terminate all processes that are consuming more than 80% of CPU. Which command should they use?",
      "options": [
        "ps -eo pid,%cpu --sort=-%cpu | awk '$2 > 80 {print $1}' | xargs kill -9",
        "top -bn1 | grep 'Cpu' | awk '{if ($2>80) print $1}' | xargs kill",
        "killall -9 highcpu",
        "htop -o %CPU"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command `ps -eo pid,%cpu --sort=-%cpu | awk '$2 > 80 {print $1}' | xargs kill -9` finds and terminates processes exceeding 80% CPU usage. `top -bn1` does not list processes directly, `killall` terminates based on names but does not filter by CPU usage, and `htop` provides an interactive interface but does not execute actions automatically.",
      "examTip": "Use `kill -15` before `kill -9` to allow processes to exit gracefully."
    },
    {
      "id": 45,
      "question": "Which command should an administrator use to configure SELinux to allow an application to bind to a non-standard port?",
      "options": [
        "semanage port -a -t http_port_t -p tcp 8080",
        "setsebool -P httpd_can_network_connect 1",
        "chcon -t httpd_sys_content_t /var/www/html",
        "restorecon -Rv /var/www/html"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`semanage port -a -t http_port_t -p tcp 8080` allows an application to bind to a non-standard port in SELinux. `setsebool` modifies boolean policies but does not assign ports, and `chcon` and `restorecon` adjust SELinux file contexts but do not manage port permissions.",
      "examTip": "Use `semanage port -l` to list currently allowed SELinux ports."
    },
    {
      "id": 46,
      "question": "A system administrator wants to restrict SSH access to only a specific group of users. Which directive should they add to `/etc/ssh/sshd_config`?",
      "options": [
        "AllowGroups sshusers",
        "PermitRootLogin no",
        "PasswordAuthentication no",
        "DenyUsers *"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `AllowGroups sshusers` directive ensures that only users in the `sshusers` group can log in via SSH. `PermitRootLogin` disables root access, `PasswordAuthentication no` enforces key-based authentication, and `DenyUsers *` blocks all users.",
      "examTip": "Restart SSH with `systemctl restart sshd` after modifying configuration settings."
    },
    {
      "id": 47,
      "question": "A system administrator needs to monitor all newly created files in `/var/log` in real time. Which command should they use?",
      "options": [
        "inotifywait -m /var/log",
        "auditctl -w /var/log -p wa",
        "ls -lt /var/log",
        "journalctl -f"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`inotifywait -m /var/log` actively monitors for new file creation events in the specified directory. `auditctl` enables auditing but does not provide real-time output, `ls -lt` lists files but does not track changes in real-time, and `journalctl` monitors logs but does not track file creation.",
      "examTip": "Use `inotifywait -e create,delete -m /var/log` for more granular monitoring."
    },
    {
      "id": 48,
      "question": "A Linux administrator needs to create a new encrypted LUKS volume and ensure it is mounted persistently. What is the correct sequence of actions?",
      "options": [
        "1) cryptsetup luksFormat /dev/sdb1 2) cryptsetup open /dev/sdb1 cryptvol 3) mkfs.ext4 /dev/mapper/cryptvol 4) echo '/dev/mapper/cryptvol /mnt/encrypted ext4 defaults 0 2' >> /etc/fstab",
        "1) mkfs.ext4 /dev/sdb1 2) cryptsetup luksFormat /dev/sdb1 3) cryptsetup open /dev/sdb1 cryptvol 4) mount /mnt/encrypted",
        "1) cryptsetup create /dev/sdb1 cryptvol 2) mkfs.ext4 /dev/sdb1 3) echo '/dev/sdb1 /mnt/encrypted ext4 defaults 0 2' >> /etc/fstab",
        "1) pvcreate /dev/sdb1 2) vgcreate luks_vg /dev/sdb1 3) lvcreate -L 10G -n cryptvol luks_vg"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct sequence involves formatting the LUKS partition, opening it, creating a filesystem, and configuring persistent mounting. Other sequences lack proper steps for encryption setup.",
      "examTip": "Use `lsblk` to verify that the encrypted volume is available before mounting."
    }

