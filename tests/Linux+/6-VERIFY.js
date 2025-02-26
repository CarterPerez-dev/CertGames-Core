db.tests.insertOne({
  "category": "linuxplus",
  "testId": 6,
  "testName": "Linux+ Practice Test #6 (Advanced)",
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
      "question": "**(PBQ)** A system administrator needs to troubleshoot a high load average issue. What is the correct sequence of actions?",
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
      "question": "**(PBQ)** A Linux administrator needs to recover a deleted user’s files from a mounted LVM snapshot. What is the correct sequence of actions?",
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
      "question": "**(PBQ)** A web server is experiencing intermittent timeouts. The administrator suspects a network bottleneck. What is the correct sequence of actions?",
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
      "question": "**(PBQ)** A Linux administrator notices that the `/var` partition is full, causing application failures. What is the correct sequence of actions?",
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
    }
  ]
});



