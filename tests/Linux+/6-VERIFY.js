db.tests.insertOne({
  "category": "linuxplus",
  "testId": 6,
  "testName": "CompTIA Linux+ (XK0-005) Practice Test #6 (Advanced)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A Linux administrator needs to ensure that a newly created user, `devops`, does not have access to the system until a specific date. Which command should they use?",
      "options": [
        "chage -E 2024-12-01 devops",
        "usermod -L devops",
        "passwd -l devops",
        "echo 'devops:!!:19315:0:99999:7:::' >> /etc/shadow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chage -E 2024-12-01 devops` sets an expiration date for the user account, preventing login after that date. `usermod -L` and `passwd -l` lock the account but do not enforce a specific expiration date, and manually modifying `/etc/shadow` is not recommended.",
      "examTip": "Use `chage -l <username>` to check the account expiration settings."
    },
    {
      "id": 2,
      "question": "Which command would allow a system administrator to find all files on the system with SUID permissions?",
      "options": [
        "find / -perm -4000 -type f",
        "ls -l / | grep 's'",
        "getfacl -R / | grep 'suid'",
        "stat --suid /usr/bin/"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find / -perm -4000 -type f` lists all files with the SUID bit set. `ls -l` does not recursively search, `getfacl` focuses on ACLs, and `stat` does not filter based on SUID.",
      "examTip": "Use `find / -perm -2000 -type f` to find SGID (Set Group ID) files."
    },
    {
      "id": 3,
      "question": "A system administrator needs to troubleshoot a high load average issue. What is the correct sequence of actions?",
      "options": [
        "1) uptime 2) top 3) ps aux --sort=-%cpu",
        "1) free -m 2) pkill -9 <process> 3) reboot",
        "1) vmstat 1 5 2) echo 3 > /proc/sys/vm/drop_caches 3) restart networking",
        "1) sar -q 2) killall -9 <process> 3) sync"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct approach is (1) checking system load with `uptime`, (2) monitoring resource usage with `top`, and (3) identifying high CPU-consuming processes with `ps aux --sort=-%cpu`.",
      "examTip": "Use `uptime` to see system load averages over 1, 5, and 15 minutes."
    },
    {
      "id": 4,
      "question": "A system administrator wants to ensure that changes made to `/etc/hosts` are immediately reflected in system resolution without restarting the system. What command should they use?",
      "options": [
        "systemctl restart nscd",
        "resolvectl flush-caches",
        "killall -HUP systemd-resolved",
        "ip route flush cache"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`resolvectl flush-caches` clears the name service cache and ensures changes to `/etc/hosts` take effect immediately. Restarting `nscd` or `systemd-resolved` can also help but may not always be necessary.",
      "examTip": "Use `getent hosts <hostname>` to verify hostname resolution using `/etc/hosts`."
    },
    {
      "id": 5,
      "question": "Which command should be used to generate a new LUKS encryption key for an existing encrypted partition?",
      "options": [
        "cryptsetup luksAddKey /dev/sdX",
        "cryptsetup luksFormat /dev/sdX",
        "dd if=/dev/urandom of=/root/keyfile bs=32 count=1",
        "echo 'NewKey123' | cryptsetup luksChangeKey /dev/sdX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`cryptsetup luksAddKey /dev/sdX` adds a new encryption key without destroying existing data. `luksFormat` would reinitialize encryption, `dd` generates a keyfile but does not apply it, and `luksChangeKey` is not a valid command.",
      "examTip": "Use `cryptsetup luksRemoveKey` to delete old keys after adding a new one."
    },
    {
      "id": 6,
      "question": "Which command will list all open files on a system, including network connections and device files?",
      "options": [
        "lsof",
        "netstat -tulnp",
        "ss -tunap",
        "fuser -m /mnt/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof` lists all open files, including regular files, network connections, and device files. `netstat` and `ss` focus on network sockets, and `fuser` checks processes using a specific mount point.",
      "examTip": "Use `lsof +D /path/to/dir` to list all open files within a directory."
    },
    {
      "id": 7,
      "question": "A user needs to check the hardware temperature of a Linux system. Which command should they use?",
      "options": [
        "sensors",
        "dmidecode -t 4",
        "lscpu",
        "uptime"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sensors` (from the `lm-sensors` package) displays CPU and system temperatures. `dmidecode -t 4` provides CPU details but not real-time temperature, `lscpu` lists CPU specs, and `uptime` reports system load averages.",
      "examTip": "Use `watch sensors` for real-time temperature monitoring."
    },
    {
      "id": 8,
      "question": "Which command should an administrator use to test if an SSH server supports a specific encryption algorithm?",
      "options": [
        "ssh -vvv user@server",
        "openssl s_client -connect server:22",
        "nmap --script ssh2-enum-algos -p 22 server",
        "nc -zv server 22"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`nmap --script ssh2-enum-algos` scans the SSH server for supported encryption algorithms. `ssh -vvv` provides detailed connection debugging, `openssl s_client` is used for TLS testing, and `nc` only tests if a port is open.",
      "examTip": "Use `ssh -Q cipher` to list supported SSH ciphers on the client."
    },
    {
      "id": 9,
      "question": "Which command allows an administrator to check the status of an NFS mount and its performance metrics?",
      "options": [
        "nfsstat",
        "showmount -e <server>",
        "df -hT",
        "mount -o remount /mnt/nfs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nfsstat` provides detailed statistics about NFS performance. `showmount` lists available shares, `df -hT` shows disk usage but not performance, and `mount -o remount` is for remounting filesystems.",
      "examTip": "Use `nfsstat -c` to view client-side NFS performance statistics."
    },
    {
      "id": 10,
      "question": "A system administrator needs to find all symbolic links pointing to a specific file. Which command should they use?",
      "options": [
        "find / -type l -lname '/path/to/file'",
        "ls -l /path/to/file",
        "stat /path/to/file",
        "readlink -f /path/to/file"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find / -type l -lname '/path/to/file'` searches for symbolic links pointing to a specific file. `ls -l` and `stat` show link details but do not find all links system-wide, and `readlink -f` resolves a single symlink.",
      "examTip": "Use `find / -xtype l` to locate broken symbolic links."
    },
    {
      "id": 11,
      "question": "A Linux administrator needs to inspect the available disk space of a Btrfs filesystem, including snapshots. Which command should they use?",
      "options": [
        "btrfs filesystem df /mnt/data",
        "df -h /mnt/data",
        "du -sh /mnt/data",
        "lsblk -f /mnt/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`btrfs filesystem df /mnt/data` provides a detailed report of disk space usage in a Btrfs filesystem, including metadata and snapshots. `df -h` shows general filesystem usage but lacks snapshot awareness.",
      "examTip": "Use `btrfs subvolume list /mnt/data` to see all Btrfs subvolumes."
    },
    {
      "id": 12,
      "question": "Which command allows a system administrator to forcefully kill a process and all of its child processes?",
      "options": [
        "pkill -9 -P <PID>",
        "kill -9 <PID>",
        "killall <process_name>",
        "xargs kill -9 < <(pgrep <process_name>)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pkill -9 -P <PID>` kills a process and all its child processes. `kill -9` only terminates a single process, `killall` targets processes by name, and `xargs` is a workaround but not the most efficient method.",
      "examTip": "Use `ps --ppid <PID>` to see child processes before terminating them."
    },
    {
      "id": 13,
      "question": "A Linux administrator needs to recover a deleted user’s files from a mounted LVM snapshot. What is the correct sequence of actions?",
      "options": [
        "1) lvcreate --snapshot -n snap01 -L 5G /dev/vg01/lv_home 2) mount /dev/vg01/snap01 /mnt/snapshot 3) cp -r /mnt/snapshot/home/user /home/user",
        "1) vgchange -ay vg01 2) lvconvert --merge /dev/vg01/snap01 3) mount -o ro /dev/vg01/lv_home /mnt/recovery",
        "1) mount /dev/vg01/snap01 /mnt/recovery 2) rsync -av /mnt/recovery/home/user /home/user 3) umount /mnt/recovery",
        "1) lvremove /dev/vg01/snap01 2) mount -o rw /dev/vg01/lv_home /mnt/data 3) rsync -av /mnt/data/home/user /home/user"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best recovery method is (1) creating a snapshot (`lvcreate --snapshot`), (2) mounting it, and (3) copying the deleted user’s files back. Other options either assume snapshots are already created or perform destructive actions.",
      "examTip": "Use `lvdisplay` to confirm available snapshots before attempting recovery."
    },
    {
      "id": 14,
      "question": "A Linux administrator wants to generate entropy for cryptographic operations quickly. Which command should they use?",
      "options": [
        "rngd -r /dev/urandom",
        "dd if=/dev/random of=/dev/null bs=1M count=10",
        "openssl rand -base64 32",
        "cat /proc/sys/kernel/random/entropy_avail"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`rngd -r /dev/urandom` increases available entropy for cryptographic operations. `/dev/random` may block if entropy is low, `openssl rand` generates a key but does not increase system entropy, and `cat /proc/sys/kernel/random/entropy_avail` only displays available entropy.",
      "examTip": "Use `cat /proc/sys/kernel/random/poolsize` to check the system’s entropy pool size."
    },
    {
      "id": 15,
      "question": "A system administrator needs to audit all commands executed by users with sudo privileges. Which configuration file should they modify?",
      "options": [
        "/etc/sudoers",
        "/var/log/auth.log",
        "/etc/security/limits.conf",
        "/etc/systemd/journald.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/sudoers` file can be configured to log all sudo commands by adding `Defaults logfile=\"/var/log/sudo.log\"`. `auth.log` stores sudo attempts but does not enable auditing.",
      "examTip": "Use `Defaults log_output` in `/etc/sudoers` to capture command output in logs."
    },
    {
      "id": 16,
      "question": "Which command is used to view the current AppArmor profile status for all running processes?",
      "options": [
        "aa-status",
        "apparmor_status",
        "getenforce",
        "lsattr"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`aa-status` displays active AppArmor profiles. `apparmor_status` is incorrect syntax, `getenforce` applies to SELinux, and `lsattr` lists file attributes but does not manage AppArmor.",
      "examTip": "Use `aa-complain <profile>` to temporarily disable an AppArmor profile without unloading it."
    },
    {
      "id": 17,
      "question": "A system administrator needs to apply a kernel update without rebooting. Which command should they use?",
      "options": [
        "kexec -l /boot/vmlinuz-<version> --initrd=/boot/initrd.img-<version> --reuse-cmdline",
        "dnf upgrade kernel",
        "grub2-mkconfig -o /boot/grub2/grub.cfg",
        "sysctl -w kernel.reload=1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`kexec` allows loading a new kernel without a full reboot. `dnf upgrade kernel` installs an update but requires a reboot, `grub2-mkconfig` regenerates the GRUB configuration, and `sysctl` does not handle kernel updates.",
      "examTip": "Use `kexec -e` to immediately switch to the new kernel after loading it."
    },
    {
      "id": 18,
      "question": "A Linux administrator needs to configure an SSH server to allow only key-based authentication and prevent root login. Which two settings should be modified in `/etc/ssh/sshd_config`?",
      "options": [
        "PermitRootLogin no, PasswordAuthentication no",
        "ChallengeResponseAuthentication no, AllowUsers admin",
        "UsePAM no, ClientAliveInterval 600",
        "RSAAuthentication yes, MaxAuthTries 2"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting `PermitRootLogin no` disables root SSH access, and `PasswordAuthentication no` enforces key-based authentication. Other settings modify authentication behavior but do not enforce key-based logins.",
      "examTip": "Use `systemctl restart sshd` after modifying `sshd_config` for changes to take effect."
    },
    {
      "id": 19,
      "question": "Which command is used to configure system-wide default permissions for newly created files and directories?",
      "options": [
        "umask",
        "chmod",
        "setfacl",
        "getfacl"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`umask` controls the default permissions assigned to new files and directories. `chmod` modifies existing permissions, `setfacl` manages access control lists, and `getfacl` retrieves ACL information.",
      "examTip": "Use `umask 027` for stricter default file permissions (750 for directories, 640 for files)."
    },
    {
      "id": 20,
      "question": "A system administrator needs to find all files modified within the last 24 hours in `/var/log`. Which command should they use?",
      "options": [
        "find /var/log -type f -mtime -1",
        "ls -lt /var/log",
        "stat /var/log/*",
        "journalctl --since '24 hours ago'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find /var/log -type f -mtime -1` locates files modified within the last 24 hours. `ls -lt` sorts files by modification time but does not filter, `stat` provides file metadata, and `journalctl` retrieves logs but not file modifications.",
      "examTip": "Use `find /var/log -type f -mmin -60` to find files modified within the last hour."
    },
    {
      "id": 21,
      "question": "A Linux administrator needs to analyze disk latency issues on an NVMe SSD. Which command provides the most detailed per-disk I/O performance statistics?",
      "options": [
        "iostat -x 1 10",
        "nvme smart-log /dev/nvme0",
        "iotop",
        "df -hT"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`nvme smart-log /dev/nvme0` retrieves SMART data specifically for NVMe devices, including latency and endurance metrics. `iostat -x` provides general disk I/O stats but lacks NVMe-specific details. `iotop` shows per-process I/O usage, and `df -hT` reports filesystem usage, not latency.",
      "examTip": "Use `nvme list` to check all available NVMe drives before running diagnostics."
    },
    {
      "id": 22,
      "question": "Which command will display all currently mounted filesystems along with their device paths and mount options?",
      "options": [
        "findmnt",
        "mount",
        "df -Th",
        "lsblk -f"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`findmnt` provides a structured view of mounted filesystems, showing device paths, mount points, and options. `mount` lists mounted files but does not include all details. `df -Th` focuses on disk usage, and `lsblk -f` shows block devices but not their mount points.",
      "examTip": "Use `findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS` to filter output."
    },
    {
      "id": 23,
      "question": "A web server is experiencing intermittent timeouts. The administrator suspects a network bottleneck. What is the correct sequence of actions?",
      "options": [
        "1) ping -c 10 <gateway> 2) traceroute <external IP> 3) ip -s link show eth0",
        "1) systemctl restart networking 2) ss -tuna 3) dig example.com",
        "1) iftop -i eth0 2) iperf3 -c <remote_host> 3) sysctl -w net.ipv4.tcp_max_syn_backlog=4096",
        "1) tcpdump -i eth0 port 443 2) arp -a 3) restart web service"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The best approach is (1) using `iftop` to check live network usage, (2) testing bandwidth with `iperf3`, and (3) tuning the TCP backlog if connection queues are full.",
      "examTip": "Use `netstat -s` to get detailed TCP connection statistics."
    },
    {
      "id": 24,
      "question": "A Linux administrator wants to run a one-time job at 3:45 AM tomorrow. Which command should they use?",
      "options": [
        "echo 'backup.sh' | at 03:45 tomorrow",
        "crontab -e",
        "systemctl start backup.timer",
        "nohup ./backup.sh &"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`echo 'backup.sh' | at 03:45 tomorrow` schedules a one-time job. `crontab -e` is for recurring jobs, `systemctl start backup.timer` assumes a pre-configured systemd timer, and `nohup` keeps a process running but does not schedule it.",
      "examTip": "Use `atq` to view scheduled `at` jobs and `atrm <job ID>` to remove them."
    },
    {
      "id": 25,
      "question": "Which command will display the current SELinux enforcement mode?",
      "options": [
        "getenforce",
        "sestatus",
        "ls -Z",
        "audit2allow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`getenforce` returns the current SELinux mode (`Enforcing`, `Permissive`, or `Disabled`). `sestatus` provides more details, `ls -Z` displays SELinux file labels, and `audit2allow` generates SELinux policies from denial logs.",
      "examTip": "Use `setenforce 0` to switch SELinux to `Permissive` mode for troubleshooting."
    },
    {
      "id": 26,
      "question": "A system administrator needs to add a new network route persistently on a Debian-based system. Which file should they modify?",
      "options": [
        "/etc/network/interfaces",
        "/etc/netplan/01-netcfg.yaml",
        "/etc/sysconfig/network-scripts/route-eth0",
        "/etc/resolv.conf"
      ],
      "correctAnswerIndex": 1,
      "explanation": "On modern Debian-based systems, network routes are configured in `/etc/netplan/01-netcfg.yaml`. `/etc/network/interfaces` is used on older systems, `/etc/sysconfig/network-scripts/route-eth0` is for RHEL-based systems, and `/etc/resolv.conf` manages DNS settings.",
      "examTip": "Use `netplan apply` after modifying network configurations."
    },
    {
      "id": 27,
      "question": "Which command will delete all stopped containers on a Docker host?",
      "options": [
        "docker container prune",
        "docker rm $(docker ps -aq)",
        "docker rmi $(docker images -q)",
        "docker system prune -a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`docker container prune` removes all stopped containers. `docker rm $(docker ps -aq)` deletes all containers, running or stopped. `docker rmi` removes images, and `docker system prune -a` removes unused containers, images, networks, and volumes.",
      "examTip": "Use `docker ps -a` to check for stopped containers before running `prune`."
    },
    {
      "id": 28,
      "question": "A Linux administrator needs to add an IP address to an interface temporarily without modifying configuration files. Which command should they use?",
      "options": [
        "ip addr add 192.168.1.100/24 dev eth0",
        "nmcli con mod eth0 ipv4.addresses 192.168.1.100/24",
        "ifconfig eth0 192.168.1.100 netmask 255.255.255.0",
        "echo '192.168.1.100 eth0' >> /etc/network/interfaces"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip addr add 192.168.1.100/24 dev eth0` adds an IP address temporarily. `nmcli con mod` makes persistent changes, `ifconfig` is deprecated, and modifying `/etc/network/interfaces` requires a restart.",
      "examTip": "Use `ip addr flush dev eth0` to remove temporary addresses."
    },
    {
      "id": 29,
      "question": "Which command will display the amount of free and used swap memory?",
      "options": [
        "free -m",
        "swapon --show",
        "vmstat -s",
        "cat /proc/swaps"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`swapon --show` provides details on active swap partitions. `free -m` shows memory usage but lacks device details, `vmstat -s` provides system statistics, and `/proc/swaps` lists swap devices without memory usage details.",
      "examTip": "Use `swapoff -a && swapon -a` to clear and reinitialize swap memory."
    },
    {
      "id": 30,
      "question": "Which command will display all failed systemd services?",
      "options": [
        "systemctl list-units --state=failed",
        "systemctl --failed",
        "journalctl -p err",
        "dmesg | grep -i failed"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`systemctl --failed` provides a quick list of failed services. `list-units --state=failed` is an alternative, `journalctl -p err` shows error logs, and `dmesg` searches kernel messages.",
      "examTip": "Use `journalctl -xe` for detailed logs of failed services."
    },
    {
      "id": 31,
      "question": "A system administrator needs to create a RAID 5 array using three disks (`/dev/sdb`, `/dev/sdc`, `/dev/sdd`). Which command should they use?",
      "options": [
        "mdadm --create --verbose /dev/md0 --level=5 --raid-devices=3 /dev/sdb /dev/sdc /dev/sdd",
        "mkfs.raid5 /dev/md0 /dev/sdb /dev/sdc /dev/sdd",
        "raidctl -C -r 5 -d /dev/sdb /dev/sdc /dev/sdd",
        "lvcreate -L 50G -n raid5_data vg_raid"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`mdadm --create --verbose` correctly sets up a RAID 5 array. `mkfs.raid5` and `raidctl` are not valid RAID creation commands in Linux, and `lvcreate` is used for LVM, not RAID.",
      "examTip": "Use `cat /proc/mdstat` to check the status of RAID arrays."
    },
    {
      "id": 32,
      "question": "Which command would a system administrator use to monitor system-wide file access in real-time?",
      "options": [
        "auditctl -w /etc/passwd -p rwxa",
        "strace -p <PID>",
        "inotifywait -m /var/log",
        "journalctl -f"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`auditctl -w /etc/passwd -p rwxa` enables auditing of file access. `strace` traces system calls of a process, `inotifywait` monitors file changes but not access, and `journalctl -f` follows system logs but does not track file access.",
      "examTip": "Use `ausearch -f /etc/passwd` to search for file access events in audit logs."
    },
    {
      "id": 33,
      "question": "A Linux administrator notices that the `/var` partition is full, causing application failures. What is the correct sequence of actions?",
      "options": [
        "1) du -sh /var/* 2) journalctl --vacuum-time=7d 3) rm -rf /var/tmp/*",
        "1) df -h 2) lvextend -L +5G /dev/vg01/var 3) resize2fs /dev/vg01/var",
        "1) systemctl stop rsyslog 2) truncate -s 0 /var/log/messages 3) systemctl start rsyslog",
        "1) fstrim -av 2) mount -o remount,rw /var 3) rm -rf /var/log/*"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The best sequence is (1) checking disk usage, (2) extending the logical volume, and (3) resizing the filesystem. Other methods clear logs but do not resolve underlying storage issues.",
      "examTip": "Use `lvdisplay` before extending a logical volume to check available free space."
    },
    {
      "id": 34,
      "question": "A Linux system running Docker has exhausted its available disk space. Which command should the administrator run to reclaim space?",
      "options": [
        "docker system prune",
        "docker container rm $(docker ps -aq)",
        "docker image prune -a",
        "docker volume prune"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`docker system prune` removes unused containers, networks, images, and build cache. `docker container rm` only removes stopped containers, `docker image prune -a` removes unused images, and `docker volume prune` cleans up unused volumes.",
      "examTip": "Use `docker system df` to check disk usage before cleaning."
    },
    {
      "id": 35,
      "question": "Which command allows an administrator to troubleshoot packet loss on a network connection?",
      "options": [
        "mtr <destination>",
        "ping -c 10 <destination>",
        "traceroute <destination>",
        "ip route show"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`mtr` provides a real-time view of network latency and packet loss. `ping` tests basic connectivity, `traceroute` shows network hops but does not continuously monitor, and `ip route show` only displays routing information.",
      "examTip": "Use `mtr -rwc 10 <destination>` for a summary report of network performance."
    },
    {
      "id": 36,
      "question": "Which command will remove all ACL permissions from a file named `secure_data.txt`?",
      "options": [
        "setfacl -b secure_data.txt",
        "setfacl -m u::r-- secure_data.txt",
        "chattr -i secure_data.txt",
        "chmod 600 secure_data.txt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`setfacl -b secure_data.txt` removes all ACLs from the file. `setfacl -m` modifies ACLs but does not remove them, `chattr -i` removes immutability, and `chmod 600` modifies traditional permissions but not ACLs.",
      "examTip": "Use `getfacl <file>` to check current ACL settings before modifying them."
    },
    {
      "id": 37,
      "question": "Which of the following actions should be taken to harden SSH security on a public-facing Linux server?",
      "options": [
        "Disable root login and enforce key-based authentication.",
        "Change the default SSH port to a non-standard port.",
        "Use TCP wrappers and firewall rules to limit access.",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed actions improve SSH security. Disabling root login and enforcing key-based authentication prevent brute-force attacks, changing the SSH port reduces scanning, and TCP wrappers/firewalls limit unauthorized access.",
      "examTip": "Use `fail2ban` to automatically ban IPs with repeated failed SSH login attempts."
    },
    {
      "id": 38,
      "question": "Which command will provide the most detailed output when diagnosing boot failures?",
      "options": [
        "journalctl -b",
        "dmesg -T",
        "systemctl status",
        "cat /var/log/boot.log"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`journalctl -b` displays logs from the most recent boot, making it the best option for diagnosing boot failures. `dmesg -T` shows kernel logs, `systemctl status` provides service details, and `/var/log/boot.log` may not exist on all distributions.",
      "examTip": "Use `journalctl -b -p 3` to filter logs for critical boot errors."
    },
    {
      "id": 39,
      "question": "A system administrator needs to schedule a script to run at system startup before any user logs in. Where should they place the script?",
      "options": [
        "/etc/rc.local",
        "/etc/init.d/",
        "/etc/systemd/system/myscript.service",
        "/etc/cron.daily/"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Creating a systemd service under `/etc/systemd/system/` ensures the script runs at boot before user login. `/etc/rc.local` is deprecated, `/etc/init.d/` is for older SysVinit systems, and `/etc/cron.daily/` schedules periodic but not startup tasks.",
      "examTip": "Use `systemctl enable myscript.service` to ensure the script runs at boot."
    },
    {
      "id": 40,
      "question": "Which of the following tools is used to automate Linux system configuration using infrastructure as code?",
      "options": [
        "Ansible",
        "Puppet",
        "Terraform",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed tools are used for automation. `Ansible` is agentless, `Puppet` requires agents, and `Terraform` is used for infrastructure provisioning.",
      "examTip": "Use `ansible-playbook` to apply configurations defined in Ansible YAML files."
    },
    {
      "id": 41,
      "question": "A system administrator needs to monitor CPU load over time and detect performance bottlenecks. Which command should they use?",
      "options": [
        "sar -u 5 10",
        "mpstat -P ALL 5 10",
        "vmstat 1 10",
        "pidstat -u 5 10"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sar -u 5 10` records CPU usage statistics at 5-second intervals, repeated 10 times. `mpstat` reports per-core CPU usage, `vmstat` provides system-wide statistics, and `pidstat` shows per-process CPU usage.",
      "examTip": "Use `sar -q` to analyze system load averages over time."
    },
    {
      "id": 42,
      "question": "Which command should be used to immediately apply changes to the GRUB bootloader configuration after modifying `/etc/default/grub`?",
      "options": [
        "grub2-mkconfig -o /boot/grub2/grub.cfg",
        "update-grub",
        "grub-install /dev/sda",
        "systemctl restart grub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`grub2-mkconfig -o /boot/grub2/grub.cfg` regenerates the GRUB configuration file. `update-grub` is used in Debian-based systems, `grub-install` reinstalls the bootloader but does not update configurations, and `systemctl restart grub` is invalid.",
      "examTip": "Use `grep GRUB_CMDLINE_LINUX /etc/default/grub` before regenerating GRUB to verify changes."
    },
    {
      "id": 43,
      "question": "A system administrator needs to troubleshoot high memory usage. What is the correct sequence of actions?",
      "options": [
        "1) free -m 2) ps aux --sort=-%mem 3) kill -9 <PID>",
        "1) vmstat 1 5 2) swapoff -a 3) reboot",
        "1) top 2) echo 3 > /proc/sys/vm/drop_caches 3) systemctl restart memcached",
        "1) sar -r 2) sysctl -w vm.overcommit_memory=2 3) sync"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best sequence is (1) checking memory usage with `free -m`, (2) identifying high-memory processes with `ps aux --sort=-%mem`, and (3) terminating problematic processes using `kill -9` if necessary.",
      "examTip": "Use `kill -15` before `kill -9` to allow a process to exit gracefully."
    },
    {
      "id": 44,
      "question": "A Linux administrator wants to limit a user’s ability to execute a specific command, even if they have sudo access. Which method should they use?",
      "options": [
        "Add a command restriction in `/etc/sudoers` using `Cmnd_Alias`.",
        "Modify `/etc/security/limits.conf` to prevent execution.",
        "Change the command’s file permissions to 700.",
        "Use `usermod -s /bin/false <user>`."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Using `Cmnd_Alias` in `/etc/sudoers` allows administrators to restrict specific commands for sudo users. `/etc/security/limits.conf` handles resource limits, not command execution, and changing file permissions affects all users.",
      "examTip": "Use `visudo` to safely edit `/etc/sudoers` and avoid syntax errors."
    },
    {
      "id": 45,
      "question": "Which command is used to inspect systemd logs from the last boot?",
      "options": [
        "journalctl -b",
        "dmesg -T",
        "cat /var/log/boot.log",
        "systemctl status boot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`journalctl -b` retrieves logs from the most recent boot. `dmesg -T` shows kernel messages, `/var/log/boot.log` may not exist on all distributions, and `systemctl status boot` is not a valid command.",
      "examTip": "Use `journalctl -b -p 3` to filter logs for critical boot errors."
    },
    {
      "id": 46,
      "question": "A system administrator needs to apply security patches without affecting currently running services. Which command should they use on a Debian-based system?",
      "options": [
        "apt-get install --only-upgrade",
        "apt-get dist-upgrade",
        "dpkg --configure -a",
        "reboot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`apt-get install --only-upgrade` upgrades installed packages without installing new ones or removing dependencies. `dist-upgrade` may alter package dependencies, `dpkg --configure -a` fixes broken installs, and `reboot` is unnecessary for most updates.",
      "examTip": "Use `apt list --upgradable` to preview updates before applying them."
    },
    {
      "id": 47,
      "question": "Which command will display all established network connections on a Linux server?",
      "options": [
        "ss -tn state established",
        "netstat -ant | grep ESTABLISHED",
        "lsof -i -P -n | grep ESTABLISHED",
        "ss -an | grep LISTEN"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ss -tn state established` shows only established TCP connections. `netstat -ant` is deprecated but works, `lsof -i` lists open network sockets, and `ss -an | grep LISTEN` filters listening connections, not established ones.",
      "examTip": "Use `ss -tan | wc -l` to count active connections quickly."
    },
    {
      "id": 48,
      "question": "Which command is used to configure a Linux server as an NTP client?",
      "options": [
        "timedatectl set-ntp true",
        "ntpd -gq",
        "systemctl enable ntpd",
        "date --set ‘2023-01-01 12:00:00’"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`timedatectl set-ntp true` enables automatic time synchronization via NTP in systemd-based systems. `ntpd -gq` forces a one-time sync, `systemctl enable ntpd` enables the service but does not configure it, and `date --set` manually sets the time.",
      "examTip": "Use `timedatectl status` to check if NTP synchronization is active."
    },
    {
      "id": 49,
      "question": "A system administrator needs to identify which process is holding a file open, preventing it from being deleted. Which command should they use?",
      "options": [
        "lsof | grep <filename>",
        "fuser -m <filename>",
        "ps aux | grep <filename>",
        "find / -name <filename> -exec rm -f {} \\;"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof | grep <filename>` lists processes using the specified file. `fuser` checks processes using a mount point, `ps aux` does not track file usage, and `find -exec rm` attempts deletion but does not diagnose the issue.",
      "examTip": "Use `lsof +D <directory>` to find all open files in a directory."
    },
    {
      "id": 50,
      "question": "Which command allows a system administrator to perform a live kernel patch on a supported Linux distribution?",
      "options": [
        "kpatch",
        "kexec -l",
        "grub2-mkconfig",
        "sysctl -w kernel.reload=1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`kpatch` applies live kernel patches without requiring a reboot. `kexec` allows switching kernels without a reboot but is not used for live patching. `grub2-mkconfig` regenerates the bootloader config, and `sysctl` does not apply kernel patches.",
      "examTip": "Use `kpatch list` to check currently applied live patches."
    },
    {
      "id": 51,
      "question": "A Linux administrator needs to force a disk partition to be re-read by the kernel without rebooting. Which command should they use?",
      "options": [
        "partprobe",
        "blkid",
        "fdisk -l",
        "sync"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`partprobe` instructs the kernel to re-read the partition table without rebooting. `blkid` displays partition UUIDs, `fdisk -l` lists partitions but does not refresh them, and `sync` flushes disk writes but does not update partition data.",
      "examTip": "Use `echo 1 > /sys/class/block/sdX/device/rescan` as an alternative for manual partition rescanning."
    },
    {
      "id": 52,
      "question": "A system administrator needs to enable SELinux in enforcing mode on a system where it was previously disabled. What steps should they take?",
      "options": [
        "1) Edit `/etc/selinux/config` and set `SELINUX=enforcing` 2) Reboot the system",
        "1) setenforce 1 2) restorecon -Rv /",
        "1) systemctl start selinux 2) sestatus",
        "1) selinux-config enable 2) reboot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting `SELINUX=enforcing` in `/etc/selinux/config` ensures SELinux is enabled on reboot. `setenforce 1` enables it temporarily but does not persist, and `restorecon` resets contexts but does not enable SELinux.",
      "examTip": "Use `sestatus` to verify SELinux mode after enabling."
    },
    {
      "id": 53,
      "question": "A system administrator needs to debug why a systemd service is failing to start. What is the correct sequence of actions?",
      "options": [
        "1) systemctl status <service> 2) journalctl -u <service> 3) systemctl restart <service>",
        "1) ps aux | grep <service> 2) systemctl start <service> 3) reboot",
        "1) dmesg | grep <service> 2) systemctl enable <service> 3) systemctl restart <service>",
        "1) systemctl stop <service> 2) systemctl disable <service> 3) rm -rf /etc/systemd/system/<service>.service"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct sequence is (1) checking the service status, (2) reviewing logs with `journalctl`, and (3) restarting the service if no issues are found. Other options include unnecessary or destructive steps.",
      "examTip": "Use `systemctl daemon-reexec` to reload systemd if a service is stuck."
    },
    {
      "id": 54,
      "question": "Which command is used to modify kernel parameters for the running system without requiring a reboot?",
      "options": [
        "sysctl -w",
        "modprobe",
        "echo 'value' > /proc/sys/kernel/parameter",
        "setsebool"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sysctl -w` modifies kernel parameters in real time. `modprobe` manages kernel modules, writing directly to `/proc/sys/` works but is not persistent, and `setsebool` is for SELinux.",
      "examTip": "Add parameters to `/etc/sysctl.conf` to make them persistent."
    },
    {
      "id": 55,
      "question": "Which command is used to generate a new pair of SSH keys using an Ed25519 algorithm?",
      "options": [
        "ssh-keygen -t ed25519",
        "openssl genrsa -out id_rsa 4096",
        "gpg --gen-key",
        "ssh-keygen -t rsa -b 4096"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ssh-keygen -t ed25519` generates an Ed25519 key, which is more secure and efficient than RSA. `openssl genrsa` creates RSA keys, `gpg --gen-key` generates PGP keys, and `ssh-keygen -t rsa` is for RSA keys.",
      "examTip": "Use `ssh-keygen -t ed25519 -C 'your_email@example.com'` to generate a key with a comment."
    },
    {
      "id": 56,
      "question": "A system administrator needs to reduce kernel log verbosity during boot. Which GRUB configuration file should they modify?",
      "options": [
        "/etc/default/grub",
        "/boot/grub2/grub.cfg",
        "/etc/grub.conf",
        "/boot/efi/EFI/grub.cfg"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifying `/etc/default/grub` allows the administrator to adjust GRUB boot parameters persistently. `grub.cfg` is auto-generated and should not be edited directly.",
      "examTip": "Run `grub2-mkconfig -o /boot/grub2/grub.cfg` after modifying `/etc/default/grub`."
    },
    {
      "id": 57,
      "question": "A Linux administrator needs to check the firmware version of a motherboard. Which command should they use?",
      "options": [
        "dmidecode -t bios",
        "lshw -class firmware",
        "lsblk",
        "modinfo bios"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`dmidecode -t bios` retrieves BIOS and firmware version details. `lshw -class firmware` provides similar output but is less commonly used, `lsblk` lists block devices, and `modinfo bios` is incorrect syntax.",
      "examTip": "Run `sudo dmidecode -t system` for detailed hardware information."
    },
    {
      "id": 58,
      "question": "Which of the following commands is used to analyze disk latency issues on a Linux system?",
      "options": [
        "iostat -x 1 10",
        "iotop",
        "smartctl -a /dev/sdX",
        "blkid"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iostat -x 1 10` provides detailed disk I/O statistics, including latency. `iotop` monitors per-process disk usage, `smartctl` checks drive health but not real-time performance, and `blkid` retrieves filesystem attributes.",
      "examTip": "Use `iostat -d -x` to get per-disk extended statistics."
    },
    {
      "id": 59,
      "question": "A Linux administrator needs to verify the container images stored locally on a system running Podman. Which command should they use?",
      "options": [
        "podman images",
        "docker images",
        "podman ps -a",
        "containerctl list-images"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`podman images` lists locally stored container images. `docker images` applies to Docker, `podman ps -a` lists containers, and `containerctl list-images` is not a valid command.",
      "examTip": "Use `podman rmi <image_id>` to remove unused container images."
    },
    {
      "id": 60,
      "question": "Which command is used to create a YAML-formatted Ansible playbook to install and start the Apache service on a Red Hat-based system?",
      "options": [
        "echo -e '- hosts: all\n  tasks:\n    - name: Install Apache\n      yum:\n        name: httpd\n        state: present\n    - name: Start Apache\n      service:\n        name: httpd\n        state: started' > install_apache.yml",
        "ansible-playbook create install_apache.yml --package httpd --state present",
        "ansible ad-hoc install httpd",
        "touch install_apache.yml && echo 'Install Apache' > install_apache.yml"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct method is using a YAML-formatted playbook with `hosts`, `tasks`, and `modules`. The other options are invalid or do not use YAML.",
      "examTip": "Use `ansible-playbook install_apache.yml` to run the playbook."
    },
    {
      "id": 61,
      "question": "A system administrator wants to disable IPv6 on a Linux server permanently. Which file should they modify?",
      "options": [
        "/etc/sysctl.conf",
        "/etc/network/interfaces",
        "/etc/hosts",
        "/etc/default/grub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Disabling IPv6 permanently requires adding `net.ipv6.conf.all.disable_ipv6 = 1` to `/etc/sysctl.conf`. `/etc/network/interfaces` configures networking but does not disable IPv6 globally, `/etc/hosts` maps hostnames, and `/etc/default/grub` configures boot parameters but is not the best approach for this.",
      "examTip": "Run `sysctl -p` after modifying `/etc/sysctl.conf` to apply changes immediately."
    },
    {
      "id": 62,
      "question": "Which command should an administrator use to display real-time CPU, memory, and network statistics in a single view?",
      "options": [
        "glances",
        "htop",
        "vmstat 1",
        "iostat -x 1 10"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`glances` provides a real-time, comprehensive view of system performance, including CPU, memory, disk, and network statistics. `htop` focuses on processes, `vmstat` reports CPU and memory usage, and `iostat` is primarily for disk I/O analysis.",
      "examTip": "Use `glances -w` to run it as a web-based monitoring tool."
    },
    {
      "id": 63,
      "question": "**(PBQ)** A Linux administrator is troubleshooting a Kubernetes pod that fails to start. What is the correct sequence of actions?",
      "options": [
        "1) kubectl get pods 2) kubectl describe pod <pod-name> 3) kubectl logs <pod-name>",
        "1) systemctl restart kubelet 2) kubectl delete pod <pod-name> 3) reboot",
        "1) kubectl run debug-session 2) docker ps -a 3) kubectl exec -it <pod-name> -- bash",
        "1) docker inspect <pod-container-id> 2) iptables -L 3) systemctl restart kubelet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking pod status, (2) describing the pod for detailed failure reasons, and (3) retrieving logs to diagnose the issue. Other sequences contain unnecessary or incorrect steps.",
      "examTip": "Use `kubectl get events --sort-by=.metadata.creationTimestamp` to see recent events."
    },
    {
      "id": 64,
      "question": "A system administrator needs to create a YAML-formatted Terraform configuration file to deploy an EC2 instance. Which tool should they use?",
      "options": [
        "terraform",
        "ansible-playbook",
        "kubectl apply",
        "packer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Terraform is used to define infrastructure as code for cloud resources like EC2 instances. `ansible-playbook` is for configuration management, `kubectl apply` manages Kubernetes, and `packer` creates machine images.",
      "examTip": "Use `terraform plan` before `terraform apply` to preview changes."
    },
    {
      "id": 65,
      "question": "Which of the following commands will display detailed information about a running container in Podman?",
      "options": [
        "podman inspect <container_id>",
        "docker ps",
        "kubectl describe pod <pod_name>",
        "ctr list"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`podman inspect <container_id>` provides detailed information about a running container. `docker ps` lists containers but lacks detailed output, `kubectl describe` is for Kubernetes pods, and `ctr list` applies to containerd but not Podman.",
      "examTip": "Use `podman logs <container_id>` to check container logs."
    },
    {
      "id": 66,
      "question": "A system administrator wants to restrict access to a directory so that only the owner can read, write, and execute files within it. Which command should they use?",
      "options": [
        "chmod 700 /restricted",
        "chown root:root /restricted",
        "setfacl -m u:admin:rwx /restricted",
        "chattr +i /restricted"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chmod 700 /restricted` ensures only the owner has full access. `chown` changes ownership but does not modify permissions, `setfacl` grants specific user access but does not restrict others, and `chattr +i` makes the directory immutable but does not restrict access.",
      "examTip": "Use `ls -ld /restricted` to verify directory permissions."
    },
    {
      "id": 67,
      "question": "Which command would a system administrator use to display detailed hardware information, including CPU model, memory, and BIOS version?",
      "options": [
        "dmidecode",
        "lscpu",
        "lsblk",
        "cat /proc/meminfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`dmidecode` provides detailed hardware information including CPU, BIOS, and memory details. `lscpu` lists CPU specifications, `lsblk` shows block devices, and `/proc/meminfo` reports memory usage but not hardware details.",
      "examTip": "Use `dmidecode -t processor` to retrieve CPU-specific details."
    },
    {
      "id": 68,
      "question": "A Linux administrator needs to identify which user is consuming the most CPU resources. Which command should they use?",
      "options": [
        "ps -eo user,%cpu --sort=-%cpu",
        "htop",
        "top -o %CPU",
        "pidstat -u"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ps -eo user,%cpu --sort=-%cpu` lists users by CPU usage. `htop` and `top` show live system usage, while `pidstat -u` provides per-process statistics.",
      "examTip": "Use `pidstat -u 1 5` to monitor CPU usage per process over time."
    },
    {
      "id": 69,
      "question": "Which command allows a user to list all mounted filesystems along with their mount options?",
      "options": [
        "findmnt",
        "df -h",
        "mount -l",
        "lsblk -f"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`findmnt` lists all mounted filesystems, showing their mount options. `df -h` displays disk space usage, `mount -l` lists mounts without options, and `lsblk -f` focuses on block devices.",
      "examTip": "Use `findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS` for a detailed view."
    },
    {
      "id": 70,
      "question": "A system administrator needs to list all services managed by systemd and their current states. Which command should they use?",
      "options": [
        "systemctl list-units --type=service",
        "systemctl list-timers",
        "systemctl list-jobs",
        "service --status-all"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=service` lists all systemd services with their current states. `systemctl list-timers` displays scheduled timers, `systemctl list-jobs` shows active jobs, and `service --status-all` is for SysVinit-based systems.",
      "examTip": "Use `systemctl list-units --failed` to see only failed services."
    },
    {
      "id": 71,
      "question": "A Linux administrator wants to configure a network interface with a static IP address persistently using Netplan. Which file should they modify?",
      "options": [
        "/etc/netplan/01-netcfg.yaml",
        "/etc/network/interfaces",
        "/etc/sysconfig/network-scripts/ifcfg-eth0",
        "/etc/resolv.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "On modern Debian-based distributions, Netplan configurations are stored in `/etc/netplan/`. `/etc/network/interfaces` is used in older systems, `/etc/sysconfig/network-scripts/` is for RHEL-based distributions, and `/etc/resolv.conf` configures DNS but not IP addresses.",
      "examTip": "After modifying Netplan configurations, apply changes with `netplan apply`."
    },
    {
      "id": 72,
      "question": "Which command will display the details of the last user who logged in to the system?",
      "options": [
        "last -n 1",
        "who",
        "w",
        "id"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`last -n 1` displays the most recent login event. `who` lists currently logged-in users, `w` provides active session details, and `id` shows user identity details but not login history.",
      "examTip": "Use `lastb` to check for failed login attempts."
    },
    {
      "id": 73,
      "question": "**(PBQ)** A system administrator needs to recover a system that fails to boot due to a missing GRUB bootloader. What is the correct sequence of actions?",
      "options": [
        "1) Boot from a live CD 2) mount /dev/sdX1 /mnt 3) grub-install --root-directory=/mnt /dev/sdX",
        "1) systemctl restart grub 2) grub2-mkconfig -o /boot/grub2/grub.cfg 3) reboot",
        "1) fsck /dev/sdX1 2) chroot /mnt 3) grub-mkrescue -o /boot/grub.img",
        "1) echo 1 > /proc/sys/kernel/boot 2) mount -o rw /boot 3) update-grub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct approach is (1) booting from a live CD, (2) mounting the root partition, and (3) reinstalling GRUB with `grub-install`. Other sequences either involve incorrect steps or assume an intact bootloader.",
      "examTip": "Use `grub2-mkconfig` after reinstalling GRUB to regenerate the config file."
    },
    {
      "id": 74,
      "question": "Which command is used to view real-time logs for a systemd-managed service?",
      "options": [
        "journalctl -u <service> -f",
        "systemctl logs <service>",
        "tail -f /var/log/syslog | grep <service>",
        "cat /run/systemd/journal/<service>.log"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`journalctl -u <service> -f` follows real-time logs for a systemd service. `systemctl logs` is incorrect syntax, `tail -f` works for syslog but may not capture all logs, and `/run/systemd/journal/` is not intended for direct viewing.",
      "examTip": "Use `journalctl -xe` to view logs for failed services."
    },
    {
      "id": 75,
      "question": "Which of the following commands will display a list of all failed login attempts?",
      "options": [
        "lastb",
        "journalctl -u sshd --grep 'Failed password'",
        "cat /var/log/auth.log | grep 'Failed password'",
        "ausearch -m USER_LOGIN --success no"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`ausearch -m USER_LOGIN --success no` retrieves all failed login attempts using audit logs. `lastb` shows failed logins but requires `btmp` to be enabled, `journalctl` works for SSH logs, and `auth.log` stores login attempts but requires filtering.",
      "examTip": "Use `fail2ban-client status sshd` if Fail2Ban is enabled."
    },
    {
      "id": 76,
      "question": "A system administrator wants to display a detailed report of disk I/O statistics, including latency and queue depth. Which command should they use?",
      "options": [
        "iostat -x 1 5",
        "iotop",
        "df -h",
        "blkid"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iostat -x 1 5` provides extended disk performance metrics, including latency and queue depth. `iotop` shows per-process disk usage, `df -h` reports filesystem usage, and `blkid` displays partition information but not performance stats.",
      "examTip": "Use `iostat -dx 1 5` to see per-device disk statistics."
    },
    {
      "id": 77,
      "question": "Which command is used to securely copy files between a local system and a remote server over SSH?",
      "options": [
        "scp",
        "rsync",
        "sftp",
        "nc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`scp` securely copies files over SSH. `rsync` can also use SSH but requires additional flags, `sftp` is an interactive file transfer tool, and `nc` is a network utility but not intended for file transfers.",
      "examTip": "Use `scp -r` to copy directories recursively."
    },
    {
      "id": 78,
      "question": "Which command will list all currently loaded kernel modules?",
      "options": [
        "lsmod",
        "modinfo",
        "modprobe -l",
        "sysctl -a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsmod` lists all loaded kernel modules. `modinfo` provides details about a specific module, `modprobe -l` lists available but not loaded modules, and `sysctl` manages kernel parameters but does not list modules.",
      "examTip": "Use `lsmod | grep <module>` to check if a specific module is loaded."
    },
    {
      "id": 79,
      "question": "A system administrator wants to check for memory errors on a running system. Which command should they use?",
      "options": [
        "dmesg | grep -i 'error'",
        "memtester 1024M",
        "journalctl -k --grep 'memory'",
        "cat /proc/meminfo"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`journalctl -k --grep 'memory'` filters system logs for memory-related errors. `dmesg` searches kernel logs but may not contain recent entries, `memtester` actively tests memory but does not check logs, and `/proc/meminfo` displays memory statistics but not errors.",
      "examTip": "Use `mcelog --ascii` to check for hardware memory errors."
    },
    {
      "id": 80,
      "question": "Which command will set a persistent DNS resolver on a Linux system using systemd-resolved?",
      "options": [
        "resolvectl dns eth0 8.8.8.8",
        "echo 'nameserver 8.8.8.8' > /etc/resolv.conf",
        "nmcli con mod eth0 ipv4.dns '8.8.8.8'",
        "systemctl restart systemd-resolved"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`resolvectl dns eth0 8.8.8.8` sets a DNS resolver persistently in `systemd-resolved`. Modifying `/etc/resolv.conf` directly may be overwritten, `nmcli` is for NetworkManager, and restarting `systemd-resolved` does not configure DNS.",
      "examTip": "Use `resolvectl status` to verify DNS settings applied to interfaces."
    },
    {
      "id": 81,
      "question": "A system administrator needs to create an LVM snapshot of `/dev/vg01/lv_data` before performing system maintenance. What is the correct command?",
      "options": [
        "lvcreate --size 10G --snapshot --name lv_backup /dev/vg01/lv_data",
        "vgcreate --snapshot --size 10G -n lv_backup /dev/vg01",
        "pvcreate --snapshot /dev/vg01/lv_data",
        "dd if=/dev/vg01/lv_data of=/backup.img"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lvcreate --size 10G --snapshot --name lv_backup /dev/vg01/lv_data` correctly creates an LVM snapshot. `vgcreate` is for volume groups, `pvcreate` initializes physical volumes but does not create snapshots, and `dd` makes a full disk copy rather than an LVM snapshot.",
      "examTip": "Use `lvremove <snapshot_name>` after testing to free up space."
    },
    {
      "id": 82,
      "question": "Which command should an administrator use to verify the status of a Kubernetes pod?",
      "options": [
        "kubectl get pods",
        "docker ps",
        "kubectl inspect pod",
        "systemctl status kubelet"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`kubectl get pods` lists Kubernetes pods and their statuses. `docker ps` lists running containers but does not provide pod-level insights, `kubectl inspect pod` is incorrect syntax, and `systemctl status kubelet` only checks the Kubelet service status.",
      "examTip": "Use `kubectl describe pod <pod-name>` for detailed pod information."
    },
    {
      "id": 83,
      "question": "**(PBQ)** A Linux server is experiencing high CPU load due to a process consuming excessive resources. What is the correct sequence of actions to diagnose and mitigate the issue?",
      "options": [
        "1) top 2) ps aux --sort=-%cpu 3) renice -n 10 <PID>",
        "1) vmstat 1 5 2) kill -9 <PID> 3) restart networking",
        "1) iotop 2) sync 3) kill -15 <PID>",
        "1) sar -q 2) sysctl -w kernel.sched_min_granularity_ns=10000000 3) reboot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) using `top` to monitor CPU load, (2) identifying high-usage processes with `ps aux --sort=-%cpu`, and (3) adjusting process priority using `renice`. Other sequences either kill processes outright or make unnecessary system modifications.",
      "examTip": "Use `nice` when launching a process and `renice` to adjust priority afterward."
    },
    {
      "id": 84,
      "question": "A system administrator needs to configure an Nginx web server to use TLS 1.3 only. Which directive should be added to the configuration file?",
      "options": [
        "ssl_protocols TLSv1.3;",
        "ssl_cipher_list HIGH:!aNULL:!MD5;",
        "ssl_enable on;",
        "tls_version 1.3 only;"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct directive is `ssl_protocols TLSv1.3;` in Nginx’s SSL configuration. `ssl_cipher_list` configures encryption ciphers but does not control protocol versions, `ssl_enable` is not a valid Nginx directive, and `tls_version` is incorrect syntax.",
      "examTip": "Use `nginx -t` after modifications to check for syntax errors before restarting."
    },
    {
      "id": 85,
      "question": "Which of the following commands will securely erase a drive to prevent data recovery?",
      "options": [
        "shred -n 3 -z /dev/sdX",
        "dd if=/dev/zero of=/dev/sdX bs=1M count=1000",
        "rm -rf /mnt/disk",
        "wipefs -a /dev/sdX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`shred -n 3 -z /dev/sdX` overwrites the drive multiple times to prevent data recovery. `dd` writes zeroes but is not as secure, `rm -rf` deletes files but does not wipe the disk, and `wipefs` removes filesystem signatures but does not erase data.",
      "examTip": "Use `hdparm --security-erase` for built-in drive erasure if supported."
    },
    {
      "id": 86,
      "question": "Which command should an administrator use to configure a firewall rule that allows incoming HTTP traffic using nftables?",
      "options": [
        "nft add rule inet filter input tcp dport 80 accept",
        "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
        "firewall-cmd --add-service=http --permanent",
        "ufw allow 80/tcp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nft add rule inet filter input tcp dport 80 accept` correctly adds an nftables rule to allow HTTP traffic. `iptables` is an older firewall tool, `firewall-cmd` is used with `firewalld`, and `ufw` is for Ubuntu’s firewall management.",
      "examTip": "Use `nft list ruleset` to verify applied firewall rules."
    },
    {
      "id": 87,
      "question": "A system administrator wants to check the status of a remote host to see if it supports TLS 1.3. Which command should they use?",
      "options": [
        "openssl s_client -connect <host>:443 -tls1_3",
        "nmap --script ssl-enum-ciphers -p 443 <host>",
        "curl -v --tlsv1.3 https://<host>",
        "testssl.sh <host>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`openssl s_client -connect <host>:443 -tls1_3` explicitly tests for TLS 1.3 support. `nmap` checks supported ciphers but does not force a specific TLS version, `curl` tests TLS in an HTTP request, and `testssl.sh` is an external tool but not a built-in command.",
      "examTip": "Use `openssl s_client -connect <host>:443 -cipher <cipher>` to test specific ciphers."
    },
    {
      "id": 88,
      "question": "Which command allows an administrator to extract and list the contents of a `.tar.gz` archive?",
      "options": [
        "tar -tzvf archive.tar.gz",
        "gzip -d archive.tar.gz",
        "tar -czvf archive.tar.gz",
        "unzip archive.tar.gz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tar -tzvf archive.tar.gz` lists the contents of a compressed archive. `gzip -d` decompresses files but does not extract, `tar -czvf` creates an archive, and `unzip` is used for `.zip` files, not `.tar.gz`.",
      "examTip": "Use `tar -xvzf archive.tar.gz` to extract the archive after listing contents."
    },
    {
      "id": 89,
      "question": "A system administrator needs to configure a Docker container to always restart if it crashes. Which option should they use?",
      "options": [
        "--restart always",
        "--restart unless-stopped",
        "--restart on-failure",
        "--restart manual"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`--restart always` ensures that a container restarts automatically whenever it stops, regardless of the reason. `unless-stopped` prevents restarts after manual stopping, `on-failure` only restarts on errors, and `manual` is not a valid restart policy.",
      "examTip": "Use `docker update --restart=always <container_id>` to change restart policies dynamically."
    },
    {
      "id": 90,
      "question": "Which command will display detailed memory allocation statistics for a running process?",
      "options": [
        "pmap -x <PID>",
        "top -p <PID>",
        "vmstat -s",
        "free -m"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pmap -x <PID>` provides detailed memory allocation per process. `top -p` shows resource usage but not detailed memory maps, `vmstat` provides system-wide memory stats, and `free` summarizes memory usage.",
      "examTip": "Use `smem -p <PID>` for a visual breakdown of a process’s memory usage."
    },
    {
      "id": 91,
      "question": "A system administrator needs to allow a non-root user to mount a specific NFS share without using sudo. Which file should they modify?",
      "options": [
        "/etc/fstab",
        "/etc/exports",
        "/etc/nfs.conf",
        "/etc/mtab"
      ],
      "correctAnswerIndex": 0,
      "explanation": "By adding the `user` option to `/etc/fstab`, non-root users can mount the specified NFS share. `/etc/exports` defines shared directories on an NFS server, `/etc/nfs.conf` configures NFS services, and `/etc/mtab` lists currently mounted filesystems but is not for configuration.",
      "examTip": "Use `mount -o user <NFS-share>` to test if a non-root user can mount the share."
    },
    {
      "id": 92,
      "question": "Which command should an administrator use to verify that IPv6 forwarding is enabled on a Linux system?",
      "options": [
        "sysctl net.ipv6.conf.all.forwarding",
        "ip a | grep inet6",
        "cat /etc/sysctl.conf | grep ipv6",
        "netstat -r | grep inet6"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sysctl net.ipv6.conf.all.forwarding` checks if IPv6 forwarding is enabled. `ip a` shows IPv6 addresses, `/etc/sysctl.conf` lists configurations but does not confirm active settings, and `netstat -r` displays routes but not forwarding status.",
      "examTip": "To enable IPv6 forwarding, use `sysctl -w net.ipv6.conf.all.forwarding=1`."
    },
    {
      "id": 93,
      "question": "**(PBQ)** A system administrator suspects a compromised SSH key on a production server. What is the correct sequence of actions to secure the system?",
      "options": [
        "1) disable SSH key authentication 2) revoke the compromised key 3) restart SSH service",
        "1) move authorized_keys to a backup location 2) update Fail2Ban rules 3) reboot the server",
        "1) change the SSH port 2) install new SSH keys 3) restart networking",
        "1) disable root login 2) reset user passwords 3) disable all active SSH sessions"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct approach is (1) disabling key authentication temporarily, (2) revoking the compromised key from `~/.ssh/authorized_keys`, and (3) restarting SSH to apply the changes.",
      "examTip": "Use `killall -u <user>` to log out all active SSH sessions of the compromised user."
    },
    {
      "id": 94,
      "question": "Which command will create a new systemd service to run a custom script at boot?",
      "options": [
        "echo -e '[Unit]\\nDescription=Custom Service\\n[Service]\\nExecStart=/usr/local/bin/myscript.sh\\n[Install]\\nWantedBy=multi-user.target' > /etc/systemd/system/myscript.service",
        "systemctl enable myscript",
        "cronjob -e '@reboot /usr/local/bin/myscript.sh'",
        "echo '/usr/local/bin/myscript.sh' >> /etc/rc.local"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Creating a service file under `/etc/systemd/system/` and defining `ExecStart` ensures the script runs at boot. `systemctl enable` makes a service persistent but does not create it, `cronjob -e` is incorrect syntax, and `/etc/rc.local` is deprecated.",
      "examTip": "Use `systemctl daemon-reload` after creating a service file to make it available."
    },
    {
      "id": 95,
      "question": "Which command allows an administrator to verify and repair filesystem corruption on an XFS partition?",
      "options": [
        "xfs_repair /dev/sdX",
        "fsck /dev/sdX",
        "e2fsck /dev/sdX",
        "btrfs check /dev/sdX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`xfs_repair` is the correct tool for checking and repairing XFS filesystems. `fsck` and `e2fsck` are used for ext-based filesystems, and `btrfs check` is for Btrfs.",
      "examTip": "Use `xfs_repair -n` for a dry run before making actual repairs."
    },
    {
      "id": 96,
      "question": "A Linux administrator needs to limit the maximum number of processes a specific user can run. Which file should they modify?",
      "options": [
        "/etc/security/limits.conf",
        "/etc/systemd/system.conf",
        "/etc/default/useradd",
        "/etc/login.defs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/security/limits.conf` file allows setting per-user limits for processes and resources. `/etc/systemd/system.conf` sets global limits, `/etc/default/useradd` defines new user defaults, and `/etc/login.defs` configures general login settings but does not limit processes.",
      "examTip": "Use `ulimit -u <limit>` to test per-session process limits."
    },
    {
      "id": 97,
      "question": "A system administrator needs to allow a specific user to run only a limited set of commands via sudo. Which file should they modify?",
      "options": [
        "/etc/sudoers",
        "/etc/security/limits.conf",
        "/etc/shadow",
        "/etc/group"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Editing `/etc/sudoers` with `visudo` allows limiting a user’s sudo commands. `/etc/security/limits.conf` restricts system resources, `/etc/shadow` stores password hashes, and `/etc/group` manages group memberships.",
      "examTip": "Use `Cmnd_Alias` in `/etc/sudoers` to restrict commands for specific users."
    },
    {
      "id": 98,
      "question": "A system administrator needs to create a persistent network route on a Red Hat-based system. Where should they define it?",
      "options": [
        "/etc/sysconfig/network-scripts/route-eth0",
        "/etc/network/interfaces",
        "/etc/sysctl.conf",
        "/etc/dhcp/dhclient.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "On Red Hat-based systems, persistent network routes are defined in `/etc/sysconfig/network-scripts/route-eth0`. `/etc/network/interfaces` is used on Debian-based systems, `/etc/sysctl.conf` modifies kernel parameters, and `/etc/dhcp/dhclient.conf` configures DHCP but not static routes.",
      "examTip": "Use `nmcli con mod eth0 ipv4.routes '192.168.1.0/24 192.168.1.1'` as an alternative for NetworkManager."
    },
    {
      "id": 99,
      "question": "Which command will list all environment variables available in the current shell session?",
      "options": [
        "printenv",
        "env",
        "export",
        "set"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`printenv` lists environment variables. `env` displays the environment for a command but does not list all variables, `export` marks variables for export but does not list them, and `set` lists shell variables, including functions and local variables.",
      "examTip": "Use `printenv | grep PATH` to check specific environment variables."
    },
    {
      "id": 100,
      "question": "Which of the following commands will configure an Ansible inventory file to use a specific SSH key for remote connections?",
      "options": [
        "echo '[web]\nserver1 ansible_host=192.168.1.10 ansible_user=admin ansible_ssh_private_key_file=/home/admin/.ssh/id_rsa' > inventory",
        "ansible-playbook -i inventory --key-file /home/admin/.ssh/id_rsa",
        "scp -i /home/admin/.ssh/id_rsa inventory remote:/etc/ansible/hosts",
        "ansible inventory set --ssh-key /home/admin/.ssh/id_rsa"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ansible inventory files specify SSH keys using `ansible_ssh_private_key_file`. `ansible-playbook` executes playbooks but does not configure inventory files, `scp` copies files but does not set SSH keys, and `ansible inventory set` is incorrect syntax.",
      "examTip": "Use `ansible-inventory --list -i inventory` to verify inventory structure."
    }
  ]
});
