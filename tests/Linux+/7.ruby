db.tests.insertOne({
  "category": "linuxplus",
  "testId": 7,
  "testName": "CompTIA Linux+ (XK0-005) Practice Test #7 (Challenging)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A system administrator needs to configure a Linux server to boot using a specific kernel version due to stability issues with the latest update. Which sequence of actions is correct?",
      "options": [
        "1) Edit `/etc/default/grub` and set `GRUB_DEFAULT='Advanced options for Ubuntu>Ubuntu, with Linux 5.15.0-48-generic'` 2) Run `update-grub` 3) Reboot",
        "1) Install an older kernel version using `dnf downgrade kernel` 2) Edit `/boot/grub2/grub.cfg` manually 3) Reboot",
        "1) Use `grubby --set-default /boot/vmlinuz-5.15.0-48-generic` 2) Run `dracut -f` 3) Restart the system",
        "1) Modify `/boot/grub/grub.cfg` directly 2) Run `sync` 3) Reboot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) modifying `/etc/default/grub` to set the desired kernel version, (2) regenerating GRUB with `update-grub`, and (3) rebooting the system. Editing `grub.cfg` directly is not recommended as it gets overwritten on updates.",
      "examTip": "Use `grubby --default-kernel` to check the currently selected default kernel."
    },
    {
      "id": 2,
      "question": "A user accidentally deleted their home directory's `.bashrc` file. Which command would restore the default system version?",
      "options": [
        "cp /etc/skel/.bashrc ~/.bashrc",
        "touch ~/.bashrc",
        "echo '' > ~/.bashrc",
        "source /etc/profile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Copying `/etc/skel/.bashrc` restores the default configuration for new users. `touch` creates an empty file, `echo ''` clears the file, and `source /etc/profile` applies global environment settings but does not restore `.bashrc`.",
      "examTip": "Use `ls -la ~` to verify if hidden files exist before restoring them."
    },
    {
      "id": 3,
      "question": "**(PBQ)** A Linux administrator needs to recover a system that is stuck in an emergency mode due to a corrupted root filesystem. What is the correct sequence of actions?",
      "options": [
        "1) Boot into rescue mode 2) Run `fsck -y /dev/sda1` 3) Reboot",
        "1) Mount the root partition manually 2) Run `chroot /mnt` 3) Reinstall GRUB",
        "1) Boot from a live CD 2) Mount the affected partition 3) Run `xfs_repair /dev/sda1`",
        "1) Edit `/etc/fstab` to disable root filesystem checks 2) Run `sync` 3) Reboot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best recovery sequence is (1) booting into rescue mode, (2) running `fsck -y` to fix filesystem errors, and (3) rebooting. Other sequences either skip required steps or assume incorrect recovery methods.",
      "examTip": "Use `mount -o remount,rw /` if the root filesystem is in read-only mode."
    },
    {
      "id": 4,
      "question": "Which command should be used to list all systemd services, including those that failed to start?",
      "options": [
        "systemctl list-units --type=service --state=failed",
        "systemctl list-timers",
        "systemctl list-sockets",
        "systemctl list-jobs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=service --state=failed` lists all failed services. `list-timers` displays scheduled jobs, `list-sockets` shows active sockets, and `list-jobs` displays queued systemd jobs.",
      "examTip": "Use `journalctl -u <service>` to get logs for a failed systemd service."
    },
    {
      "id": 5,
      "question": "Which command should an administrator use to configure auditd to monitor all modifications to the `/etc/passwd` file?",
      "options": [
        "auditctl -w /etc/passwd -p wa -k passwd_changes",
        "ausearch --file /etc/passwd",
        "auditd --monitor /etc/passwd",
        "journalctl --grep '/etc/passwd'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`auditctl -w /etc/passwd -p wa -k passwd_changes` configures auditd to monitor writes and attribute changes. `ausearch` retrieves past events but does not set monitoring rules, and `journalctl` does not replace auditd.",
      "examTip": "Use `auditctl -l` to list active audit rules."
    },
    {
      "id": 6,
      "question": "A Linux administrator needs to troubleshoot an NFS mount failure. Which log file should they check first?",
      "options": [
        "/var/log/messages",
        "/var/log/nfslog",
        "/var/log/dmesg",
        "/etc/exports"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In many distributions, NFS errors are logged in `/var/log/messages`. `/var/log/nfslog` may contain additional details, `/var/log/dmesg` shows kernel messages but does not track NFS errors, and `/etc/exports` defines shares but does not store logs.",
      "examTip": "Use `journalctl -u nfs-server` for systemd-based logging of NFS errors."
    },
    {
      "id": 7,
      "question": "Which command should be used to analyze the CPU scheduling behavior of a specific process?",
      "options": [
        "pidstat -p <PID>",
        "ps -eo pid,comm,pri,nice",
        "top -p <PID>",
        "renice -n 10 <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pidstat -p <PID>` provides real-time statistics on CPU scheduling for a specific process. `ps -eo` lists process priorities but does not show scheduling history, `top -p` monitors resource usage, and `renice` modifies process priority but does not analyze behavior.",
      "examTip": "Use `pidstat -u 1 5` to collect CPU usage data over time."
    },
    {
      "id": 8,
      "question": "A system administrator wants to reduce the amount of system journal logs stored on a server. Which command should they use?",
      "options": [
        "journalctl --vacuum-time=7d",
        "journalctl --delete-old",
        "rm -rf /var/log/journal",
        "truncate -s 0 /var/log/journal"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`journalctl --vacuum-time=7d` removes logs older than 7 days. `journalctl --delete-old` is incorrect syntax, `rm -rf` is destructive, and `truncate` clears files but does not manage log retention.",
      "examTip": "Use `journalctl --disk-usage` to check how much space logs are consuming."
    },
    {
      "id": 9,
      "question": "Which command will test an open port on a remote system without establishing a full connection?",
      "options": [
        "nc -zv <host> <port>",
        "telnet <host> <port>",
        "ping -p <port> <host>",
        "ss -tunap | grep <port>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nc -zv <host> <port>` checks if a remote port is open without sending data. `telnet` establishes a full connection, `ping -p` does not exist, and `ss -tunap` lists sockets but does not actively test connectivity.",
      "examTip": "Use `nmap -p <port> <host>` for a more detailed scan."
    },
    {
      "id": 10,
      "question": "A system administrator needs to analyze why a recently scheduled systemd timer did not execute. Which command should they use first?",
      "options": [
        "systemctl list-timers --all",
        "journalctl -u <timer-name>",
        "systemctl start <timer-name>",
        "atq"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-timers --all` lists all systemd timers, including inactive ones. `journalctl -u` checks logs but does not list scheduled timers, `systemctl start` runs a timer immediately but does not diagnose execution failures, and `atq` is for `at` jobs, not systemd timers.",
      "examTip": "Use `systemctl cat <timer-name>.timer` to inspect timer configurations."
    },
    {
      "id": 11,
      "question": "A Linux administrator wants to determine whether a process is consuming excessive file descriptors. Which command should they use?",
      "options": [
        "lsof -p <PID>",
        "ulimit -n",
        "ls -l /proc/<PID>/fd",
        "pmap <PID>"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`ls -l /proc/<PID>/fd` lists all open file descriptors for a process, helping to diagnose excessive resource usage. `lsof -p` also lists open files but does not count descriptors, `ulimit -n` checks limits but not usage, and `pmap` provides memory mappings.",
      "examTip": "Use `ls -l /proc/self/fd` to check the current shell’s open file descriptors."
    },
    {
      "id": 12,
      "question": "**(PBQ)** A Linux system is experiencing extremely slow I/O performance. What is the correct sequence of actions to diagnose and resolve the issue?",
      "options": [
        "1) iostat -x 1 5 2) fstrim -av 3) mount -o remount,noatime /",
        "1) top 2) swapoff -a 3) reboot",
        "1) systemctl stop udev 2) fsck -y /dev/sda1 3) restart networking",
        "1) dd if=/dev/zero of=/testfile bs=1M count=1024 2) smartctl -H /dev/sda 3) clear_cache"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best troubleshooting sequence is (1) checking disk I/O performance with `iostat`, (2) running `fstrim` to optimize SSD performance, and (3) remounting the filesystem with `noatime` to reduce disk writes.",
      "examTip": "Use `iostat -dx 1 5` to get per-device extended disk statistics."
    },
    {
      "id": 13,
      "question": "Which of the following commands is used to list all available systemd targets?",
      "options": [
        "systemctl list-units --type=target",
        "systemctl get-default",
        "runlevel",
        "who -r"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=target` lists all available systemd targets. `systemctl get-default` shows the current default target, `runlevel` applies to SysVinit, and `who -r` provides similar information but is less commonly used.",
      "examTip": "Use `systemctl set-default <target>` to change the default boot target."
    },
    {
      "id": 14,
      "question": "Which command will display detailed statistics about memory allocation per process?",
      "options": [
        "pmap -x <PID>",
        "top -p <PID>",
        "vmstat -s",
        "free -m"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pmap -x <PID>` provides detailed memory allocation per process, including resident and shared memory usage. `top -p` shows process usage but lacks breakdowns, `vmstat` provides system-wide memory stats, and `free` summarizes system memory usage.",
      "examTip": "Use `smem -p <PID>` for a visual breakdown of a process’s memory usage."
    },
    {
      "id": 15,
      "question": "A Linux administrator needs to verify whether an SSH server supports a specific encryption algorithm. Which command should they use?",
      "options": [
        "nmap --script ssh2-enum-algos -p 22 <host>",
        "openssl s_client -connect <host>:22",
        "ssh -vvv user@host",
        "nc -zv <host> 22"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nmap --script ssh2-enum-algos -p 22 <host>` scans the SSH server to list supported encryption algorithms. `openssl s_client` tests TLS/SSL but not SSH, `ssh -vvv` provides debugging output but does not list supported algorithms, and `nc` only tests if the port is open.",
      "examTip": "Use `ssh -Q cipher` to list supported SSH ciphers on the client."
    },
    {
      "id": 16,
      "question": "A system administrator wants to configure a scheduled task using Ansible that runs a script every day at midnight. Which module should they use?",
      "options": [
        "cron",
        "at",
        "systemd",
        "script"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `cron` module in Ansible is used to schedule recurring jobs. `at` schedules one-time jobs, `systemd` manages services but not cron jobs, and `script` executes standalone scripts but does not schedule them.",
      "examTip": "Use `ansible -m cron -a 'name=backup job=\"/usr/local/bin/backup.sh\" minute=0 hour=0'` to set up a cron job via Ansible."
    },
    {
      "id": 17,
      "question": "Which command is used to verify that a system is using the correct TLS certificate for a web server?",
      "options": [
        "openssl s_client -connect <host>:443",
        "curl -v https://<host>",
        "sslyze <host>",
        "nmap --script ssl-cert -p 443 <host>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`openssl s_client -connect <host>:443` retrieves and displays the TLS certificate. `curl -v` shows details but lacks in-depth certificate analysis, `sslyze` is an external tool, and `nmap --script ssl-cert` extracts certificate details but does not test the connection.",
      "examTip": "Use `openssl x509 -in cert.pem -noout -text` to inspect a certificate locally."
    },
    {
      "id": 18,
      "question": "Which command should an administrator use to set a specific CPU core affinity for a process?",
      "options": [
        "taskset -c 1,3 <command>",
        "nice -n 10 <command>",
        "schedtool -a 1 <command>",
        "renice -n -5 <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`taskset -c 1,3 <command>` assigns a process to specific CPU cores. `nice` and `renice` modify process priority, while `schedtool` is an alternative but less common method.",
      "examTip": "Use `taskset -p <PID>` to check the CPU affinity of an existing process."
    },
    {
      "id": 19,
      "question": "A Linux administrator needs to expand the root Logical Volume (LV) by 20GB on a server running a mission-critical database. The existing Volume Group (VG) has unallocated space, and the root LV uses an ext4 filesystem. Which sequence of steps would correctly expand the LV and the ext4 filesystem without downtime?",
      "options": [
        "1) pvcreate /dev/sdb; 2) vgextend myVG /dev/sdb; 3) lvresize -r -L +20G /dev/myVG/root; 4) resize2fs /dev/myVG/root",
        "1) lvextend -L +20G /dev/myVG/root; 2) pvcreate /dev/sdb; 3) resize2fs /dev/myVG/root; 4) vgextend myVG /dev/sdb",
        "1) vgextend myVG /dev/sdb; 2) pvcreate /dev/sdb; 3) resize2fs /dev/myVG/root; 4) lvresize -r -L +20G /dev/myVG/root",
        "1) pvcreate /dev/sdb; 2) vgextend myVG /dev/sdb; 3) lvextend -r -L +20G /dev/myVG/root; 4) resize2fs /dev/myVG/root"
      ],
      "correctAnswerIndex": 3,
      "explanation": "First, you must convert the new disk partition to a physical volume (pvcreate) and then extend the Volume Group (vgextend) with that PV. Next, extending the Logical Volume (lvextend or lvresize with -r) automatically updates the filesystem. If the -r flag is used, resize2fs is invoked automatically; however, it’s listed as a separate step for clarity. Ensuring the correct sequence of pvcreate -> vgextend -> lvextend -> filesystem resize is crucial.",
      "examTip": "Use the '-r' (resizefs) option when extending or reducing LVM volumes for ext-based filesystems to streamline the process. Always verify available free extents in the Volume Group before resizing."
    },
    {
      "id": 20,
      "question": "A server has two interfaces, eth0 (192.168.10.10/24) and eth1 (10.10.0.10/24). The administrator wants to route all traffic to 192.168.20.0/24 via eth0 and all traffic to 10.10.1.0/24 via eth1. The default gateway is on 192.168.10.1. Which configuration steps ensure persistent routing for these two subnets?",
      "options": [
        "1) Add 'ip route add 192.168.20.0/24 dev eth0' and 'ip route add 10.10.1.0/24 dev eth1'; 2) Add default route to 192.168.10.1; 3) Place these commands in /etc/rc.local for persistence.",
        "1) Edit /etc/sysconfig/network-scripts/ifcfg-eth0 and ifcfg-eth1 with static routes; 2) Add 'GATEWAY=192.168.10.1' under eth0; 3) Add '10.10.1.0/24 via 10.10.0.1 dev eth1'; 4) Add '192.168.20.0/24 via 192.168.10.1 dev eth0' in respective route files.",
        "1) Delete all default routes and rely on dynamic routing; 2) Enable RIP or OSPF for multi-homed subnets; 3) Set GATEWAY=10.10.0.1 in ifcfg-eth1; 4) Let the router broadcast routes via RIP.",
        "1) Manually add 'ip route add 10.10.1.0/24 dev eth1' and remove any default route; 2) Configure iptables to NAT traffic to 192.168.20.0/24; 3) Save the firewall rule; 4) Use DHCP for the default gateway on eth0."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Creating persistent static routes on Red Hat-based systems (and many others) involves configuring route files or using the 'ifcfg-ethX' scripts. Each subnet is directed to the appropriate interface, and the default gateway is set under the primary interface (eth0). Steps that rely on dynamic routing or manual additions to /etc/rc.local are less maintainable and can be error-prone, especially if network-scripts are expected to handle routing on startup.",
      "examTip": "For persistent static routes on RPM-based distros, use dedicated route files or the ifcfg- interface scripts. On Debian-based systems, routes can go in /etc/network/interfaces or /etc/netplan/*. Always confirm your default gateway is on the correct interface."
    },
    {
      "id": 21,
      "question": "A Linux system is configured with multiple network interfaces. The administrator needs to force all outbound traffic to a specific interface (`eth1`). Which command should they use?",
      "options": [
        "ip route add default via 192.168.1.1 dev eth1",
        "ifconfig eth1 up",
        "iptables -A OUTPUT -o eth1 -j ACCEPT",
        "nmcli con mod eth1 ipv4.gateway 192.168.1.1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip route add default via 192.168.1.1 dev eth1` sets the default route for outbound traffic to go through `eth1`. `ifconfig eth1 up` brings up the interface but does not set routing, `iptables` does not configure routing, and `nmcli` modifies gateway settings but does not directly set the default route.",
      "examTip": "Use `ip route show` to verify current routing before making changes."
    },
    {
      "id": 22,
      "question": "A Linux administrator needs to test connectivity to an NTP server and verify the current system time. Which command should they use?",
      "options": [
        "chronyc tracking",
        "timedatectl show",
        "ntpq -p",
        "hwclock --show"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chronyc tracking` provides details on the system’s NTP synchronization status. `timedatectl show` displays time settings but does not verify NTP connectivity, `ntpq -p` works with `ntpd`, and `hwclock --show` checks the hardware clock but not NTP status.",
      "examTip": "Use `chronyc sources` to list active NTP sources and their offsets."
    },
    {
      "id": 23,
      "question": "**(PBQ)** A system administrator needs to troubleshoot why a system is failing to mount a network share at boot. What is the correct sequence of actions?",
      "options": [
        "1) cat /etc/fstab 2) mount -a 3) journalctl -xe | grep mount",
        "1) systemctl restart nfs-client 2) ls /mnt/share 3) reboot",
        "1) umount -l /mnt/share 2) df -h 3) rm -rf /mnt/share",
        "1) ip link set eth0 down 2) echo 1 > /proc/sys/fs/nfs/debug 3) dmesg | grep 'mount error'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best sequence is (1) checking `/etc/fstab` for incorrect entries, (2) using `mount -a` to attempt mounting all filesystems, and (3) reviewing logs for errors. Other sequences contain unnecessary or destructive actions.",
      "examTip": "Use `showmount -e <server>` to check if the NFS share is available."
    },
    {
      "id": 24,
      "question": "A system administrator needs to grant a user permission to restart the `nginx` service without full root privileges. Which file should they modify?",
      "options": [
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/security/limits.conf",
        "/etc/systemd/system/nginx.service"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/sudoers` file allows defining granular sudo privileges. Modifying `/etc/passwd` does not affect permissions, `/etc/security/limits.conf` controls resource limits, and `/etc/systemd/system/nginx.service` defines service configurations but not access control.",
      "examTip": "Use `visudo` to safely edit `/etc/sudoers` and avoid syntax errors."
    },
    {
      "id": 25,
      "question": "A Linux administrator needs to determine the number of available processors for system tuning. Which command should they use?",
      "options": [
        "nproc",
        "lscpu",
        "cat /proc/cpuinfo | grep processor",
        "dmidecode -t processor"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nproc` quickly returns the number of available processor cores. `lscpu` provides detailed CPU information, `cat /proc/cpuinfo | grep processor` lists cores but requires manual counting, and `dmidecode` retrieves hardware details but is not the most efficient way to check processor count.",
      "examTip": "Use `nproc --all` to display all available logical processors."
    },
    {
      "id": 26,
      "question": "Which command should an administrator use to list all enabled systemd timers?",
      "options": [
        "systemctl list-timers",
        "systemctl list-units --type=timer",
        "crontab -l",
        "atq"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`systemctl list-units --type=timer` displays all enabled timers. `systemctl list-timers` lists active timers, `crontab -l` lists cron jobs, and `atq` shows scheduled `at` jobs but not systemd timers.",
      "examTip": "Use `systemctl list-timers --all` to include inactive timers."
    },
    {
      "id": 27,
      "question": "Which command allows an administrator to securely erase a specific file by overwriting it multiple times?",
      "options": [
        "shred -n 3 -z file.txt",
        "rm -rf file.txt",
        "wipe file.txt",
        "truncate -s 0 file.txt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`shred -n 3 -z file.txt` securely overwrites the file three times before deleting it. `rm -rf` deletes the file but does not prevent recovery, `wipe` is an alternative tool but not installed by default, and `truncate` clears a file’s content but does not erase data securely.",
      "examTip": "Use `shred -u file.txt` to overwrite and remove the file in one step."
    },
    {
      "id": 28,
      "question": "A Linux system needs to be configured with a custom DNS resolver while ignoring `/etc/resolv.conf` changes from DHCP. Which command should be used?",
      "options": [
        "resolvectl dns eth0 8.8.8.8",
        "nmcli con mod eth0 ipv4.dns 8.8.8.8",
        "echo 'nameserver 8.8.8.8' > /etc/resolv.conf",
        "systemctl restart systemd-resolved"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`resolvectl dns eth0 8.8.8.8` sets a custom DNS resolver in `systemd-resolved`, preventing DHCP from modifying it. `nmcli` works for NetworkManager-managed interfaces, modifying `/etc/resolv.conf` directly may get overwritten, and restarting `systemd-resolved` does not set DNS.",
      "examTip": "Use `resolvectl status` to verify applied DNS settings."
    },
    {
      "id": 29,
      "question": "Which command allows an administrator to check if a service is enabled to start at boot on a systemd-based system?",
      "options": [
        "systemctl is-enabled <service>",
        "systemctl status <service>",
        "chkconfig <service> --list",
        "ls /etc/systemd/system/"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl is-enabled <service>` checks whether a service is configured to start at boot. `systemctl status` checks if it's running, `chkconfig` is for older systems, and `ls /etc/systemd/system/` lists service unit files but does not indicate enablement.",
      "examTip": "Use `systemctl enable <service>` to set a service to start at boot."
    },
    {
      "id": 30,
      "question": "A Linux administrator needs to schedule a system reboot at 2:30 AM tomorrow without creating a cron job. Which command should they use?",
      "options": [
        "echo 'shutdown -r 02:30' | at now + 1 day",
        "systemctl schedule reboot.timer",
        "nohup shutdown -r 02:30 &",
        "cronjob -e '@reboot shutdown -r'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`echo 'shutdown -r 02:30' | at now + 1 day` schedules a one-time reboot using `at`. `systemctl schedule` is not a valid command, `nohup` keeps processes running but does not schedule events, and `cronjob -e` is incorrect syntax.",
      "examTip": "Use `atq` to list pending `at` jobs and `atrm <job ID>` to remove a scheduled task."
    },
    {
      "id": 31,
      "question": "Which command is used to monitor the number of TCP connections in various states (e.g., ESTABLISHED, TIME_WAIT, LISTEN)?",
      "options": [
        "ss -s",
        "netstat -an | grep tcp",
        "ip route show",
        "tcpdump -i eth0"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ss -s` provides a summary of TCP connection states. `netstat -an | grep tcp` lists raw connections but does not summarize states, `ip route show` displays routing tables, and `tcpdump` captures packets but does not analyze TCP state counts.",
      "examTip": "Use `ss -ant state established` to filter for active connections."
    },
    {
      "id": 32,
      "question": "**(PBQ)** A Linux server is running out of available PIDs, causing process failures. What is the correct sequence of actions to diagnose and mitigate the issue?",
      "options": [
        "1) cat /proc/sys/kernel/pid_max 2) sysctl -w kernel.pid_max=500000 3) systemctl restart systemd-logind",
        "1) ps aux --sort=-%mem 2) pkill -9 <process> 3) echo 500000 > /proc/sys/kernel/pid_max",
        "1) sysctl -a | grep pid 2) echo 500000 > /etc/sysctl.conf 3) killall -9 systemd-logind",
        "1) uptime 2) kill -15 <PID> 3) systemctl daemon-reexec"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking the current PID limit, (2) increasing it temporarily using `sysctl -w`, and (3) restarting system services if necessary. Other sequences include unnecessary or destructive steps.",
      "examTip": "Use `echo 500000 > /proc/sys/kernel/pid_max` to apply changes immediately."
    },
    {
      "id": 33,
      "question": "A system administrator wants to configure a system to log every executed command, including its timestamp and the user who ran it. Which file should they modify?",
      "options": [
        "/etc/bashrc",
        "/etc/profile",
        "/etc/audit/rules.d/audit.rules",
        "/etc/logrotate.conf"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Configuring auditing in `/etc/audit/rules.d/audit.rules` ensures every executed command is logged. `bashrc` and `profile` affect shell behavior but do not enforce logging, and `logrotate.conf` manages log rotation but does not enable command auditing.",
      "examTip": "Use `auditctl -a always,exit -F arch=b64 -S execve -k command_exec` to enable command logging."
    },
    {
      "id": 34,
      "question": "A system administrator needs to allow a user to run a script at startup without requiring a password for sudo. Which file should they modify?",
      "options": [
        "/etc/sudoers",
        "/etc/crontab",
        "/etc/systemd/system/",
        "/etc/environment"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding a rule to `/etc/sudoers` with `NOPASSWD` allows a user to run a command without entering a password. `/etc/crontab` schedules tasks but does not control sudo privileges, `/etc/systemd/system/` contains service files, and `/etc/environment` sets global variables.",
      "examTip": "Use `visudo` to safely edit the sudoers file and avoid syntax errors."
    },
    {
      "id": 35,
      "question": "Which command should a system administrator use to check the CPU affinity of a running process?",
      "options": [
        "taskset -p <PID>",
        "ps -eo pid,psr,comm",
        "top -o %CPU",
        "renice -n 5 -p <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`taskset -p <PID>` displays or sets the CPU affinity of a process. `ps -eo` lists CPU cores assigned to processes, `top -o %CPU` sorts processes by CPU usage, and `renice` changes process priority but does not manage CPU affinity.",
      "examTip": "Use `taskset -c 0,1 <command>` to run a process on specific CPU cores."
    },
    {
      "id": 36,
      "question": "A system administrator needs to troubleshoot a Kubernetes pod that is stuck in a `CrashLoopBackOff` state. What should they do first?",
      "options": [
        "kubectl describe pod <pod-name>",
        "kubectl delete pod <pod-name>",
        "systemctl restart kubelet",
        "docker ps -a | grep <pod-name>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`kubectl describe pod <pod-name>` provides details on why a pod is failing, including error messages and restart counts. `kubectl delete pod` removes the pod but does not diagnose the issue, `systemctl restart kubelet` restarts the Kubernetes service but does not solve pod failures, and `docker ps` shows containers but lacks Kubernetes-level details.",
      "examTip": "Use `kubectl logs <pod-name>` to see detailed logs for a failing pod."
    },
    {
      "id": 37,
      "question": "A Linux administrator needs to restrict SSH access so that only users in the `admin` group can log in. Which configuration file should they modify?",
      "options": [
        "/etc/ssh/sshd_config",
        "/etc/security/access.conf",
        "/etc/pam.d/sshd",
        "/etc/hosts.allow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifying `/etc/ssh/sshd_config` with `AllowGroups admin` ensures only users in the `admin` group can log in via SSH. `/etc/security/access.conf` controls general system access, `/etc/pam.d/sshd` affects PAM authentication but not group restrictions, and `/etc/hosts.allow` manages IP-based access but not user restrictions.",
      "examTip": "Restart SSH with `systemctl restart sshd` after modifying `sshd_config`."
    },
    {
      "id": 38,
      "question": "A system administrator needs to configure automatic rotation of logs for a custom application. Which file should they modify?",
      "options": [
        "/etc/logrotate.d/custom_app",
        "/var/log/custom_app.log",
        "/etc/rsyslog.conf",
        "/etc/systemd/journald.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Log rotation rules should be defined in `/etc/logrotate.d/custom_app`. Modifying `/var/log/custom_app.log` does not configure rotation, `/etc/rsyslog.conf` manages log forwarding but not rotation, and `/etc/systemd/journald.conf` configures journald but not custom log rotation.",
      "examTip": "Use `logrotate -d /etc/logrotate.d/custom_app` to test log rotation settings."
    },
    {
      "id": 39,
      "question": "A Linux administrator needs to check if a specific TCP port is open on a remote server without establishing a full connection. Which command should they use?",
      "options": [
        "nc -zv <host> <port>",
        "telnet <host> <port>",
        "curl -I http://<host>:<port>",
        "ping -p <port> <host>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nc -zv <host> <port>` tests if a port is open without sending data. `telnet` attempts to establish a connection, `curl -I` is for HTTP headers, and `ping -p` does not exist.",
      "examTip": "Use `nmap -p <port> <host>` for a more detailed scan."
    },
    {
      "id": 40,
      "question": "A system administrator needs to analyze a core dump file from a crashed application. Which command should they use?",
      "options": [
        "gdb /path/to/binary /path/to/core",
        "strace -p <PID>",
        "dmesg | grep segfault",
        "journalctl --since '1 hour ago'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`gdb /path/to/binary /path/to/core` loads a core dump into GDB for analysis. `strace` traces system calls but does not analyze dumps, `dmesg` shows kernel messages but not detailed analysis, and `journalctl` provides logs but does not debug binaries.",
      "examTip": "Use `ulimit -c unlimited` to enable core dumps if they are not being generated."
    },
    {
      "id": 41,
      "question": "**(PBQ)** A Linux system is experiencing intermittent network failures. What is the correct sequence of actions to diagnose and resolve the issue?",
      "options": [
        "1) ip link show 2) ethtool eth0 3) dmesg | grep eth0",
        "1) ifconfig eth0 down 2) reboot 3) ip link set eth0 up",
        "1) tcpdump -i eth0 2) killall -9 NetworkManager 3) restart networking",
        "1) systemctl stop networking 2) edit /etc/network/interfaces 3) systemctl start networking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best troubleshooting sequence is (1) checking the link status with `ip link show`, (2) using `ethtool` to check the NIC settings, and (3) checking system logs for hardware or driver issues.",
      "examTip": "Use `dmesg | grep eth0` to look for network-related errors."
    },
    {
      "id": 42,
      "question": "A Linux administrator needs to modify an existing SSH configuration to enforce key-based authentication while disabling password logins. Which configuration file should they modify?",
      "options": [
        "/etc/ssh/sshd_config",
        "/etc/security/access.conf",
        "/etc/pam.d/sshd",
        "/etc/hosts.allow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `sshd_config` file controls SSH settings, including authentication. Adding `PasswordAuthentication no` enforces key-based authentication. `/etc/security/access.conf` controls general access rules, `/etc/pam.d/sshd` modifies PAM rules, and `/etc/hosts.allow` manages IP-based access.",
      "examTip": "Restart SSH with `systemctl restart sshd` after modifying `sshd_config`."
    },
    {
      "id": 43,
      "question": "A system administrator needs to set up an automated remote backup using rsync over SSH while preserving file attributes. Which command should they use?",
      "options": [
        "rsync -avz -e 'ssh' /data/ user@remote:/backup/",
        "scp -r /data/ user@remote:/backup/",
        "tar -czf backup.tar.gz /data/ && scp backup.tar.gz user@remote:/backup/",
        "dd if=/dev/sda | ssh user@remote 'dd of=/backup.img'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`rsync -avz -e 'ssh' /data/ user@remote:/backup/` efficiently transfers files while preserving permissions and attributes. `scp` copies files but lacks incremental updates, `tar` creates archives but is not real-time, and `dd` is used for disk cloning, not file syncing.",
      "examTip": "Use `rsync --delete` to remove files on the remote that no longer exist on the source."
    },
    {
      "id": 44,
      "question": "Which command allows an administrator to list all files opened by a specific process?",
      "options": [
        "lsof -p <PID>",
        "ps aux | grep <PID>",
        "strace -p <PID>",
        "fuser -m <file>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof -p <PID>` lists all files opened by a specific process. `ps aux` shows process details but not file usage, `strace` traces system calls, and `fuser` identifies processes using a specific file but does not list all opened files.",
      "examTip": "Use `lsof +D /path/to/dir` to list all open files within a directory."
    },
    {
      "id": 45,
      "question": "A system administrator needs to enforce disk quotas on a multi-user system. Which file should they modify?",
      "options": [
        "/etc/fstab",
        "/etc/quotas.conf",
        "/etc/security/limits.conf",
        "/etc/default/useradd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding `usrquota` or `grpquota` options to `/etc/fstab` enables disk quotas. `/etc/quotas.conf` is not a standard configuration file, `/etc/security/limits.conf` controls resource limits but not disk quotas, and `/etc/default/useradd` defines default user settings.",
      "examTip": "Run `quotacheck -avug` after enabling quotas to initialize the quota database."
    },
    {
      "id": 46,
      "question": "Which command should a system administrator use to monitor disk I/O statistics for all mounted filesystems in real time?",
      "options": [
        "iostat -x 1",
        "iotop",
        "vmstat -d 1",
        "df -i"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iostat -x 1` provides per-disk I/O statistics in real time, including utilization and wait times. `iotop` shows per-process disk usage, `vmstat -d` reports system-wide disk activity, and `df -i` displays inode usage but not disk performance.",
      "examTip": "Use `iostat -dx 1` for per-device extended disk I/O details."
    },
    {
      "id": 47,
      "question": "A Linux administrator needs to investigate a sudden increase in TCP retransmissions on a server. Which command should they use first?",
      "options": [
        "ss -s",
        "netstat -s | grep 'segments retransmited'",
        "tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-rst) != 0'",
        "ip -s link show eth0"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`netstat -s | grep 'segments retransmited'` shows TCP retransmissions, which can indicate network congestion or packet loss. `ss -s` gives a TCP state summary, `tcpdump` captures packets but does not summarize retransmissions, and `ip -s link show` provides interface statistics but not TCP-specific data.",
      "examTip": "Use `tcptrace` for an in-depth TCP retransmission analysis."
    },
    {
      "id": 48,
      "question": "A Linux administrator needs to create a snapshot of a Btrfs filesystem before applying a risky system update. Which command should they use?",
      "options": [
        "btrfs subvolume snapshot /mnt/data /mnt/data_snapshot",
        "lvcreate --snapshot --size 5G -n data_snapshot /dev/vg01/lv_data",
        "tar -czf data_backup.tar.gz /mnt/data",
        "rsync -a /mnt/data /mnt/data_backup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`btrfs subvolume snapshot /mnt/data /mnt/data_snapshot` creates a snapshot of a Btrfs subvolume instantly. `lvcreate` is used for LVM snapshots, `tar` creates a backup but not a snapshot, and `rsync` copies files but does not preserve filesystem features.",
      "examTip": "Use `btrfs subvolume list /mnt/data` to check available snapshots."
    },
    {
      "id": 49,
      "question": "**(PBQ)** A system administrator needs to troubleshoot excessive CPU usage caused by a specific process. What is the correct sequence of actions?",
      "options": [
        "1) top 2) ps -eo pid,%cpu,command --sort=-%cpu 3) renice -n 10 <PID>",
        "1) vmstat 1 5 2) kill -9 <PID> 3) reboot",
        "1) iotop 2) sync 3) kill -15 <PID>",
        "1) sar -u 2) sysctl -w kernel.sched_latency_ns=5000000 3) reboot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best troubleshooting sequence is (1) monitoring CPU usage with `top`, (2) identifying high-usage processes with `ps`, and (3) adjusting process priority using `renice`. Other sequences either forcefully kill processes or reboot without diagnosing the issue.",
      "examTip": "Use `renice` instead of `kill` whenever possible to prevent abrupt process terminations."
    },
    {
      "id": 50,
      "question": "A Linux administrator needs to configure a firewall rule using `nftables` to allow only incoming HTTPS traffic. Which command should they use?",
      "options": [
        "nft add rule inet filter input tcp dport 443 accept",
        "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
        "firewall-cmd --add-service=https --permanent",
        "ufw allow 443/tcp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nft add rule inet filter input tcp dport 443 accept` adds a rule to allow HTTPS traffic using `nftables`. `iptables` is an older firewall tool, `firewall-cmd` is for `firewalld`, and `ufw` is specific to Ubuntu-based distributions.",
      "examTip": "Use `nft list ruleset` to verify firewall rules applied with `nftables`."
    },
    {
      "id": 51,
      "question": "Which command will provide detailed statistics about memory allocation per process?",
      "options": [
        "pmap -x <PID>",
        "top -p <PID>",
        "vmstat -s",
        "free -m"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pmap -x <PID>` provides a detailed memory map of a process, including resident and shared memory. `top -p <PID>` shows real-time memory usage, `vmstat -s` gives system-wide memory statistics, and `free` displays total memory usage but not per-process details.",
      "examTip": "Use `pmap -d <PID>` for a detailed breakdown of memory usage."
    },
    {
      "id": 52,
      "question": "A system administrator suspects that a user is running unauthorized network scans. Which command should they use to monitor suspicious activity?",
      "options": [
        "tcpdump -i eth0 'port 22 or port 443'",
        "lsof -i -n -P",
        "netstat -ant | grep SYN_RECV",
        "journalctl -u sshd --since '30 minutes ago'"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`lsof -i -n -P` lists all open network connections and their associated processes, helping to identify unauthorized scans. `tcpdump` captures traffic but does not correlate it with processes, `netstat` lists TCP connections but lacks process details, and `journalctl` checks logs but does not monitor active connections.",
      "examTip": "Use `lsof -i | grep LISTEN` to check which processes are listening for connections."
    },
    {
      "id": 53,
      "question": "A Linux administrator wants to display real-time network usage per process. Which command should they use?",
      "options": [
        "nethogs",
        "iftop",
        "bmon",
        "ss -tuna"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nethogs` displays real-time bandwidth usage by process, making it ideal for monitoring network-intensive applications. `iftop` shows per-host network usage, `bmon` provides interface statistics, and `ss` lists network sockets but does not track per-process usage.",
      "examTip": "Use `nethogs -d 2` to refresh network usage data every 2 seconds."
    },
    {
      "id": 54,
      "question": "Which command should an administrator use to check the current SELinux mode on a system?",
      "options": [
        "getenforce",
        "sestatus",
        "ls -Z /etc/passwd",
        "audit2allow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`getenforce` returns the current SELinux mode (`Enforcing`, `Permissive`, or `Disabled`). `sestatus` provides a more detailed status, `ls -Z` shows file SELinux labels, and `audit2allow` helps generate policies but does not display mode status.",
      "examTip": "Use `setenforce 0` to temporarily switch to permissive mode for troubleshooting."
    },
    {
      "id": 55,
      "question": "A Linux administrator needs to restrict SSH access so only users in the `developers` group can log in. Which configuration should they modify?",
      "options": [
        "Edit `/etc/ssh/sshd_config` and add `AllowGroups developers`",
        "Modify `/etc/security/access.conf` to allow only `developers`",
        "Change `/etc/pam.d/sshd` to enforce group-based login policies",
        "Edit `/etc/passwd` to assign all users to the `developers` group"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding `AllowGroups developers` to `/etc/ssh/sshd_config` ensures only users in that group can log in via SSH. `access.conf` and PAM configurations can restrict access but are not specific to SSH, and modifying `/etc/passwd` does not enforce SSH restrictions.",
      "examTip": "Restart SSH with `systemctl restart sshd` after modifying `sshd_config`."
    },
    {
      "id": 56,
      "question": "Which command should an administrator use to verify which Linux capabilities are assigned to a binary?",
      "options": [
        "getcap /usr/bin/ping",
        "lsattr /usr/bin/ping",
        "stat /usr/bin/ping",
        "captest --print"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`getcap /usr/bin/ping` displays assigned capabilities, such as `CAP_NET_RAW`, allowing execution without full root privileges. `lsattr` shows file attributes, `stat` provides metadata but not capabilities, and `captest` checks process capabilities but does not inspect files.",
      "examTip": "Use `setcap cap_net_raw+ep /usr/bin/ping` to grant the `CAP_NET_RAW` capability."
    },
    {
      "id": 57,
      "question": "**(PBQ)** A system administrator suspects that a scheduled cron job is not executing correctly. What is the correct sequence of actions to diagnose the issue?",
      "options": [
        "1) crontab -l 2) grep CRON /var/log/syslog 3) run the job manually",
        "1) systemctl restart crond 2) check `/etc/crontab` 3) reboot",
        "1) atq 2) chmod +x /etc/cron.daily/job 3) reschedule the job",
        "1) ls -lh /var/spool/cron 2) reset crontab permissions 3) restart networking"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) verifying the cron job with `crontab -l`, (2) checking logs for execution errors, and (3) running the job manually to confirm functionality. Other sequences contain unnecessary or incorrect steps.",
      "examTip": "Use `run-parts --test /etc/cron.daily/` to check scheduled job execution."
    },
    {
      "id": 58,
      "question": "A system administrator needs to set up a firewall rule using `iptables` to allow all incoming SSH traffic. Which command should they use?",
      "options": [
        "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
        "iptables -I INPUT 1 -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT",
        "iptables --flush INPUT",
        "iptables -P INPUT ACCEPT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iptables -A INPUT -p tcp --dport 22 -j ACCEPT` allows all incoming SSH connections. `-I INPUT 1` inserts the rule at the top but limits it to a subnet, `--flush` removes all rules, and `-P INPUT ACCEPT` sets a default policy but does not define specific rules.",
      "examTip": "Use `iptables-save` to persist firewall rules across reboots."
    },
    {
      "id": 59,
      "question": "A Linux administrator needs to verify which kernel modules are currently loaded. Which command should they use?",
      "options": [
        "lsmod",
        "modinfo",
        "modprobe -l",
        "sysctl -a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsmod` lists all currently loaded kernel modules. `modinfo` provides details on a specific module, `modprobe -l` lists available but not necessarily loaded modules, and `sysctl` manages kernel parameters but does not list modules.",
      "examTip": "Use `lsmod | grep <module>` to check if a specific module is loaded."
    },
    {
      "id": 60,
      "question": "Which command allows an administrator to identify and analyze performance bottlenecks related to high CPU utilization over time?",
      "options": [
        "sar -u 5 10",
        "vmstat 1 5",
        "top -n 5",
        "mpstat -P ALL 5 10"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sar -u 5 10` records CPU usage statistics at 5-second intervals, repeated 10 times, helping identify patterns of high CPU utilization over time. `vmstat` and `mpstat` provide useful data but are less effective for long-term analysis.",
      "examTip": "Use `sar -q` to analyze system load averages over time."
    },
    {
      "id": 61,
      "question": "A system administrator needs to configure automatic failover for an Nginx web server using Keepalived. Which configuration file should they modify?",
      "options": [
        "/etc/keepalived/keepalived.conf",
        "/etc/nginx/nginx.conf",
        "/etc/systemd/system/keepalived.service",
        "/etc/network/interfaces"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The Keepalived service uses `/etc/keepalived/keepalived.conf` to configure failover and VRRP settings. `/etc/nginx/nginx.conf` is for web server settings, `/etc/systemd/system/keepalived.service` controls the service, and `/etc/network/interfaces` manages IP configurations but not failover.",
      "examTip": "Use `systemctl enable keepalived` to ensure it starts at boot."
    },
    {
      "id": 62,
      "question": "A Linux administrator needs to audit all login attempts on a system and generate reports. Which tool should they use?",
      "options": [
        "ausearch -m USER_LOGIN",
        "journalctl -u sshd",
        "faillog",
        "lastb"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ausearch -m USER_LOGIN` retrieves all login attempts recorded by the audit daemon. `journalctl -u sshd` shows SSH-specific logs, `faillog` reports failed login attempts but does not generate full audit reports, and `lastb` shows failed login attempts but is not an auditing tool.",
      "examTip": "Use `auditctl -a always,exit -F arch=b64 -S execve -k login_attempts` to audit login-related commands."
    },
    {
      "id": 63,
      "question": "A system administrator wants to ensure that user `jdoe` cannot execute commands as root using `sudo`. Which action should they take?",
      "options": [
        "Remove `jdoe` from `/etc/sudoers` or the `sudo` group.",
        "Set `umask 077` in `/etc/profile` for `jdoe`.",
        "Modify `/etc/passwd` to change `jdoe`'s shell to `/bin/false`.",
        "Edit `/etc/security/limits.conf` to restrict `jdoe`'s process limits."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Removing `jdoe` from the sudoers file or `sudo` group prevents them from executing commands as root. Setting `umask` restricts file permissions but does not affect `sudo`, changing the shell prevents interactive login but not command execution, and modifying `limits.conf` restricts system resources but not root access.",
      "examTip": "Use `visudo` to safely edit `/etc/sudoers` and avoid syntax errors."
    },
    {
      "id": 64,
      "question": "Which command allows an administrator to determine which process is consuming the most disk I/O on a Linux system?",
      "options": [
        "iotop",
        "iostat -dx 1 10",
        "vmstat 1 5",
        "df -hT"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iotop` displays real-time disk I/O usage per process. `iostat` provides disk performance metrics but does not show per-process usage, `vmstat` reports system-wide statistics but not specific I/O usage per process, and `df` only displays disk space usage.",
      "examTip": "Use `iotop -o` to filter and display only processes actively performing disk I/O."
    },
    {
      "id": 65,
      "question": "**(PBQ)** A Linux server is experiencing repeated segmentation faults when running a critical application. What is the correct sequence of actions to diagnose and resolve the issue?",
      "options": [
        "1) dmesg | grep segfault 2) strace -p <PID> 3) gdb /path/to/binary core.dump",
        "1) systemctl restart application 2) top -o %MEM 3) echo 3 > /proc/sys/vm/drop_caches",
        "1) journalctl -u application 2) fsck -y /dev/sda1 3) reboot",
        "1) ps aux --sort=-%cpu 2) renice -n 10 <PID> 3) sysctl -w kernel.panic=1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best troubleshooting sequence is (1) checking kernel logs for segfault errors, (2) using `strace` to trace system calls of the failing process, and (3) analyzing the core dump with `gdb` to determine the cause.",
      "examTip": "Ensure `ulimit -c unlimited` is set to enable core dumps for debugging."
    },
    {
      "id": 66,
      "question": "Which command should a Linux administrator use to check for and clear zombie processes on a system?",
      "options": [
        "ps aux | awk '$8 ~ /Z/ {print $2}' | xargs kill -9",
        "killall -9 zombie",
        "top | grep zombie | awk '{print $1}' | xargs kill -9",
        "strace -p <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct method is using `ps aux` to filter zombie processes (`Z` state) and `kill -9` to remove their parent processes. `killall` does not work on zombie processes directly, and `strace` is useful for debugging but does not clear them.",
      "examTip": "If zombie processes persist, restart the parent process or the system."
    },
    {
      "id": 67,
      "question": "A Linux administrator needs to configure a firewall rule that allows inbound SSH connections only from a specific IP address (`192.168.1.100`). Which command should they use?",
      "options": [
        "iptables -A INPUT -s 192.168.1.100 -p tcp --dport 22 -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
        "iptables -D INPUT -s 192.168.1.100 -p tcp --dport 22 -j ACCEPT",
        "firewall-cmd --permanent --add-service=ssh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iptables -A INPUT -s 192.168.1.100 -p tcp --dport 22 -j ACCEPT` allows SSH access only from the specified IP. The second option allows all SSH traffic, the third removes a rule instead of adding one, and `firewall-cmd` is for `firewalld`, not iptables.",
      "examTip": "Use `iptables-save` to persist firewall rules across reboots."
    },
    {
      "id": 68,
      "question": "A system administrator needs to verify the integrity of all installed RPM packages. Which command should they use?",
      "options": [
        "rpm -Va",
        "yum check-update",
        "dnf verify",
        "rpm --rebuilddb"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`rpm -Va` verifies the integrity of all installed RPM packages. `yum check-update` lists available updates but does not verify files, `dnf verify` is not a valid command, and `rpm --rebuilddb` recreates the RPM database but does not check file integrity.",
      "examTip": "Look for missing files or modified binaries in the output of `rpm -Va`."
    },
    {
      "id": 69,
      "question": "A system administrator needs to determine which process is using the most swap space on a Linux server. Which command should they use?",
      "options": [
        "smem -s swap -r",
        "free -m",
        "top -o %MEM",
        "vmstat -s"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`smem -s swap -r` sorts processes by swap usage. `free -m` shows total swap usage but not per-process details, `top -o %MEM` sorts by memory but does not isolate swap, and `vmstat -s` reports system-wide memory statistics.",
      "examTip": "Use `grep VmSwap /proc/*/status` to check swap usage manually."
    },
    {
      "id": 70,
      "question": "A Linux administrator needs to configure an Ansible playbook to create a new user on multiple servers. Which module should they use?",
      "options": [
        "user",
        "shell",
        "command",
        "lineinfile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `user` module in Ansible is used to create and manage users. `shell` and `command` execute arbitrary commands but are not ideal for user creation, and `lineinfile` modifies files but does not create users.",
      "examTip": "Use `ansible -m user -a 'name=jdoe state=present'` to create a user via Ansible."
    },
    {
      "id": 71,
      "question": "A Linux administrator needs to modify the default kernel parameters related to memory management and make the changes persistent across reboots. Which file should they edit?",
      "options": [
        "/etc/sysctl.conf",
        "/boot/grub2/grub.cfg",
        "/etc/security/limits.conf",
        "/etc/default/kernel"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Modifying `/etc/sysctl.conf` ensures kernel parameters persist across reboots. `/boot/grub2/grub.cfg` is for boot settings, `/etc/security/limits.conf` controls user resource limits, and `/etc/default/kernel` does not exist.",
      "examTip": "Use `sysctl -p` after modifying `/etc/sysctl.conf` to apply changes immediately."
    },
    {
      "id": 72,
      "question": "Which command should an administrator use to display detailed statistics about system calls made by a running process?",
      "options": [
        "strace -p <PID>",
        "lsof -p <PID>",
        "ps aux | grep <PID>",
        "vmstat 1 5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`strace -p <PID>` traces system calls made by a process. `lsof` lists open files, `ps aux` shows process details, and `vmstat` provides system-wide resource statistics but not system calls.",
      "examTip": "Use `strace -c -p <PID>` for a summary of system calls."
    },
    {
      "id": 73,
      "question": "**(PBQ)** A Linux administrator needs to diagnose a storage performance issue affecting a production database. What is the correct sequence of actions?",
      "options": [
        "1) iostat -dx 1 10 2) blkdiscard /dev/sdX 3) fstrim -v /",
        "1) smartctl -H /dev/sdX 2) iostat -x 1 5 3) mount -o remount,noatime /db",
        "1) df -h 2) fsck -y /dev/sdX 3) reboot",
        "1) journalctl -u storage 2) dd if=/dev/zero of=/testfile bs=1M count=1000 3) rm -rf /var/cache"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The best approach is (1) checking disk health with `smartctl`, (2) analyzing disk I/O with `iostat`, and (3) tuning mount options like `noatime` to reduce write overhead.",
      "examTip": "Use `fio` for advanced benchmarking of disk I/O performance."
    },
    {
      "id": 74,
      "question": "A system administrator wants to configure an immutable file in `/var/log` to prevent accidental modification or deletion. Which command should they use?",
      "options": [
        "chattr +i /var/log/secure",
        "chmod 000 /var/log/secure",
        "setfacl -m u::r-- /var/log/secure",
        "ln -s /dev/null /var/log/secure"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chattr +i` makes a file immutable, preventing modification or deletion. `chmod 000` removes permissions but does not prevent root from modifying the file, `setfacl` modifies access control lists, and linking to `/dev/null` redirects writes but does not protect the file.",
      "examTip": "Use `lsattr` to check if a file has immutable attributes set."
    },
    {
      "id": 75,
      "question": "Which command allows an administrator to identify which process is consuming the most network bandwidth in real time?",
      "options": [
        "nethogs",
        "iftop",
        "bmon",
        "ss -tuna"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nethogs` shows real-time per-process network bandwidth usage. `iftop` monitors per-host network usage, `bmon` provides interface statistics, and `ss -tuna` lists network sockets but does not show per-process bandwidth.",
      "examTip": "Use `nethogs -d 2` to refresh network usage data every 2 seconds."
    },
    {
      "id": 76,
      "question": "A Linux administrator needs to configure a firewall rule to allow incoming HTTPS traffic on a system using firewalld. Which command should they use?",
      "options": [
        "firewall-cmd --permanent --add-service=https",
        "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
        "ufw allow 443/tcp",
        "nft add rule inet filter input tcp dport 443 accept"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`firewall-cmd --permanent --add-service=https` is the correct command for firewalld-based systems. `iptables` is for older firewall implementations, `ufw` is for Ubuntu-based systems, and `nft` applies to nftables.",
      "examTip": "Use `firewall-cmd --reload` to apply changes after modifying firewalld rules."
    },
    {
      "id": 77,
      "question": "Which command allows an administrator to analyze active connections on a system and detect potential network abuse?",
      "options": [
        "ss -tuna",
        "netstat -antp",
        "lsof -i",
        "tcpdump -i eth0"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`tcpdump -i eth0` captures real-time network packets, making it useful for detecting malicious traffic. `ss -tuna` and `netstat -antp` list connections but do not analyze traffic content, and `lsof -i` shows which processes have open network sockets.",
      "examTip": "Use `tcpdump -nn -i eth0 port 22` to capture SSH traffic specifically."
    },
    {
      "id": 78,
      "question": "A Linux administrator needs to securely transfer an entire directory to a remote server while preserving permissions and symbolic links. Which command should they use?",
      "options": [
        "rsync -avz /data/ user@remote:/backup/",
        "scp -r /data/ user@remote:/backup/",
        "tar -czf backup.tar.gz /data/ && scp backup.tar.gz user@remote:/backup/",
        "dd if=/dev/sda | ssh user@remote 'dd of=/backup.img'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`rsync -avz /data/ user@remote:/backup/` efficiently transfers directories while preserving file attributes and symbolic links. `scp` lacks efficient synchronization, `tar` compresses data but does not sync files, and `dd` is used for disk cloning, not directory transfers.",
      "examTip": "Use `rsync --delete` to remove files from the remote destination that no longer exist on the source."
    },
    {
      "id": 79,
      "question": "A Linux administrator needs to determine if a binary file has been tampered with by comparing its cryptographic hash to a known good value. Which command should they use?",
      "options": [
        "sha256sum /usr/bin/example",
        "diff /usr/bin/example /backup/usr/bin/example",
        "lsattr /usr/bin/example",
        "strings /usr/bin/example"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sha256sum /usr/bin/example` generates a cryptographic hash that can be compared to a known good hash. `diff` compares file content but is not reliable for binary files, `lsattr` lists file attributes but does not verify integrity, and `strings` extracts readable text but does not check file integrity.",
      "examTip": "Use `rpm -V <package>` on RPM-based systems to verify installed binaries."
    },
    {
      "id": 80,
      "question": "Which command should an administrator use to monitor detailed system resource usage, including CPU, memory, and I/O, in real time?",
      "options": [
        "glances",
        "htop",
        "vmstat 1",
        "sar -u 1 5"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`glances` provides real-time monitoring of CPU, memory, disk, and network usage in a single view. `htop` focuses on process management, `vmstat` provides system performance data but lacks a user-friendly interface, and `sar` collects historical performance data.",
      "examTip": "Use `glances -w` to launch a web-based monitoring dashboard."
    },
    {
      "id": 81,
      "question": "**(PBQ)** A system administrator suspects unauthorized access to a server and needs to identify recent login attempts. What is the correct sequence of actions?",
      "options": [
        "1) last -a | grep 'still logged in' 2) journalctl -u sshd --since '1 hour ago' 3) faillog -a",
        "1) cat /var/log/auth.log 2) netstat -ant 3) killall -u suspicious_user",
        "1) who -a 2) echo 'ALL: ALL' >> /etc/hosts.deny 3) systemctl restart sshd",
        "1) ps aux | grep ssh 2) tcpdump -i eth0 port 22 3) ban iptables -A INPUT -s <ip> -j DROP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking logged-in users with `last -a`, (2) reviewing SSH logs for failed login attempts, and (3) using `faillog` to check for login failures.",
      "examTip": "Use `grep 'Failed password' /var/log/auth.log` to detect brute-force attempts."
    },
    {
      "id": 82,
      "question": "A system administrator wants to scan a system for rootkits. Which tool should they use?",
      "options": [
        "rkhunter",
        "chkrootkit",
        "lynis",
        "clamav"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`rkhunter` scans for known rootkits and security vulnerabilities. `chkrootkit` is another rootkit scanner but lacks active monitoring, `lynis` is a general security auditing tool, and `clamav` is an antivirus tool but not designed for rootkit detection.",
      "examTip": "Use `rkhunter --update && rkhunter --check` for the latest definitions before scanning."
    },
    {
      "id": 83,
      "question": "A Linux administrator wants to identify open ports on a remote system and check for vulnerabilities. Which command should they use?",
      "options": [
        "nmap -sV -p- <host>",
        "ss -tulnp",
        "netstat -antp",
        "iptables -L -n -v"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nmap -sV -p- <host>` scans all ports and detects running services. `ss -tulnp` lists active network connections locally, `netstat` shows TCP connections but does not perform a vulnerability scan, and `iptables` lists firewall rules but does not scan for open ports.",
      "examTip": "Use `nmap --script vuln <host>` to check for known vulnerabilities."
    },
    {
      "id": 84,
      "question": "A Linux administrator needs to automatically restart a service if it crashes. Which systemd directive should they add to the service unit file?",
      "options": [
        "Restart=always",
        "OnFailure=restart",
        "AutoRestart=yes",
        "RestartSec=0"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`Restart=always` ensures that a service restarts if it crashes. `OnFailure=restart` is incorrect syntax, `AutoRestart=yes` is not a valid systemd option, and `RestartSec=0` sets a delay but does not enable automatic restarts.",
      "examTip": "Use `systemctl daemon-reload` after modifying a systemd service file."
    },
    {
      "id": 85,
      "question": "A Linux administrator wants to create a new LVM volume and ensure it is mounted automatically at boot. What is the correct sequence of actions?",
      "options": [
        "1) lvcreate -L 50G -n data vg01 2) mkfs.ext4 /dev/vg01/data 3) echo '/dev/vg01/data /mnt/data ext4 defaults 0 2' >> /etc/fstab",
        "1) vgcreate vg01 /dev/sdb1 2) lvextend -L +10G /dev/vg01/data 3) mount -a",
        "1) pvcreate /dev/sdb1 2) vgextend vg01 /dev/sdb1 3) mkfs.ext4 /dev/vg01/data",
        "1) fdisk /dev/sdb 2) partprobe /dev/sdb 3) reboot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct approach is (1) creating the LVM volume, (2) formatting it, and (3) adding it to `/etc/fstab` for automatic mounting. Other sequences either lack formatting or involve incorrect steps.",
      "examTip": "Use `mount -a` after modifying `/etc/fstab` to test the configuration."
    },
    {
      "id": 86,
      "question": "A Linux administrator wants to monitor file changes in `/var/www/html` and trigger an action when a file is modified. Which tool should they use?",
      "options": [
        "inotifywait -m /var/www/html",
        "auditctl -w /var/www/html -p wa -k web_changes",
        "tripwire --check",
        "rsync -av --checksum /var/www/html backup:/var/www/html"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`auditctl -w /var/www/html -p wa -k web_changes` sets up auditing for file modifications. `inotifywait` can monitor changes but does not store logs, `tripwire` detects integrity violations but does not trigger real-time actions, and `rsync` is used for backups.",
      "examTip": "Use `ausearch -k web_changes` to retrieve audit logs for monitored files."
    },
    {
      "id": 87,
      "question": "A Linux administrator suspects a disk failure and needs to retrieve SMART data from `/dev/sdb`. Which command should they use?",
      "options": [
        "smartctl -a /dev/sdb",
        "fsck -y /dev/sdb",
        "blkid /dev/sdb",
        "tune2fs -l /dev/sdb"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`smartctl -a /dev/sdb` provides detailed SMART data, which helps assess disk health. `fsck` checks for filesystem errors, `blkid` shows partition attributes, and `tune2fs` displays filesystem parameters but not hardware health.",
      "examTip": "Use `smartctl -t long /dev/sdb` to perform an extended disk health test."
    },
    {
      "id": 88,
      "question": "Which command allows an administrator to configure a persistent static route on a Debian-based system?",
      "options": [
        "echo '192.168.1.0/24 via 192.168.1.1' >> /etc/network/interfaces",
        "ip route add 192.168.1.0/24 via 192.168.1.1",
        "nmcli con mod eth0 ipv4.routes '192.168.1.0/24 192.168.1.1'",
        "route add -net 192.168.1.0/24 gw 192.168.1.1"
      ],
      "correctAnswerIndex": 2,
      "explanation": "For NetworkManager-managed interfaces, `nmcli con mod eth0 ipv4.routes` ensures persistent static routes. `ip route add` is temporary, `route add -net` is deprecated, and modifying `/etc/network/interfaces` directly is no longer the recommended method.",
      "examTip": "Use `nmcli con up eth0` after modifying routes to apply changes immediately."
    },
    {
      "id": 89,
      "question": "**(PBQ)** A system administrator needs to identify why a newly added storage device is not being recognized. What is the correct sequence of actions?",
      "options": [
        "1) lsblk 2) dmesg | grep sdX 3) partprobe /dev/sdX",
        "1) fdisk -l 2) mount /dev/sdX /mnt 3) reboot",
        "1) mkfs.ext4 /dev/sdX 2) df -h 3) resize2fs /dev/sdX",
        "1) lvcreate -L 10G -n storage vg01 2) mount -a 3) systemctl restart udev"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) listing block devices with `lsblk`, (2) checking system logs with `dmesg`, and (3) using `partprobe` to force a rescan. Other sequences involve unnecessary or incorrect steps.",
      "examTip": "Use `udevadm settle` to ensure device initialization completes before mounting."
    },
    {
      "id": 90,
      "question": "A Linux administrator needs to configure sudo access for a specific user without modifying the global sudoers file. Where should they create a configuration file?",
      "options": [
        "/etc/sudoers.d/<username>",
        "/etc/sudoers",
        "/etc/security/limits.conf",
        "/etc/passwd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Creating a file in `/etc/sudoers.d/` allows per-user sudo configuration without modifying `/etc/sudoers`. `limits.conf` is for resource limits, and `/etc/passwd` does not handle sudo access.",
      "examTip": "Use `visudo -f /etc/sudoers.d/<username>` to safely edit sudo rules."
    },
    {
      "id": 91,
      "question": "Which command should an administrator use to enable detailed auditing of all commands executed by a specific user?",
      "options": [
        "auditctl -a always,exit -F arch=b64 -S execve -F auid=<UID> -k user_commands",
        "journalctl -u auditd --since '1 hour ago'",
        "ausearch -m EXECVE -ua <UID>",
        "tail -f /var/log/audit/audit.log"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`auditctl -a always,exit -F arch=b64 -S execve -F auid=<UID>` logs every executed command for the specified user. `journalctl` retrieves logs but does not enable auditing, `ausearch` queries logs but does not configure rules, and `tail` monitors logs but does not enable tracking.",
      "examTip": "Use `auditctl -l` to list active audit rules."
    },
    {
      "id": 92,
      "question": "A Linux administrator needs to configure a containerized application to restart automatically if it crashes. Which option should they use with `docker run`?",
      "options": [
        "--restart unless-stopped",
        "--restart always",
        "--restart on-failure",
        "--restart manual"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`--restart on-failure` ensures that the container restarts only if it crashes. `unless-stopped` prevents automatic restarts if manually stopped, `always` restarts under any condition, and `manual` is not a valid restart policy.",
      "examTip": "Use `docker update --restart=on-failure <container>` to modify an existing container’s restart policy."
    },
    {
      "id": 93,
      "question": "Which command allows an administrator to determine whether a system is running as a virtual machine?",
      "options": [
        "systemd-detect-virt",
        "virt-what",
        "dmidecode -s system-manufacturer",
        "lsmod | grep kvm"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemd-detect-virt` detects if the system is running inside a VM. `virt-what` provides similar functionality but may require additional installation, `dmidecode` shows hardware details but not VM status, and `lsmod | grep kvm` checks if KVM is loaded but does not determine VM presence.",
      "examTip": "Use `systemd-detect-virt --vm` to check for virtualized environments specifically."
    },
    {
      "id": 94,
      "question": "Which command should an administrator use to dynamically change the priority of a running process?",
      "options": [
        "renice -n 10 -p <PID>",
        "nice -n 10 <command>",
        "kill -SIGSTOP <PID>",
        "schedtool -n 10 -p <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`renice -n 10 -p <PID>` adjusts the priority of a running process. `nice` sets priority when launching a process, `kill -SIGSTOP` pauses a process but does not change priority, and `schedtool` can modify scheduling policies but is less commonly used.",
      "examTip": "Use `ps -eo pid,ni,comm` to check process priority before modifying it."
    },
    {
      "id": 95,
      "question": "A Linux administrator needs to investigate why a system service failed at boot. Which command should they run first?",
      "options": [
        "journalctl -b -u <service>",
        "systemctl restart <service>",
        "dmesg | grep <service>",
        "tail -f /var/log/syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`journalctl -b -u <service>` retrieves logs for a specific service since the last boot. `systemctl restart` attempts to restart the service without identifying the root cause, `dmesg` provides kernel logs but may not capture service failures, and `syslog` may not contain systemd service logs.",
      "examTip": "Use `systemctl status <service>` for a quick summary before checking logs."
    },
    {
      "id": 96,
      "question": "Which command should an administrator use to change the primary group of an existing user?",
      "options": [
        "usermod -g <group> <user>",
        "groupmod -g <group> <user>",
        "gpasswd -a <user> <group>",
        "chgrp <group> <file>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`usermod -g <group> <user>` modifies a user's primary group. `groupmod` changes group properties, `gpasswd -a` adds a user to a group but does not modify the primary group, and `chgrp` changes file group ownership but not user settings.",
      "examTip": "Use `id <user>` to verify group memberships after modification."
    },
    {
      "id": 97,
      "question": "**(PBQ)** A Linux system is running out of inode space, causing file creation failures. What is the correct sequence of actions to diagnose and resolve the issue?",
      "options": [
        "1) df -i 2) find / -xdev -type d -exec du --inodes {} + 3) remove unnecessary files",
        "1) fsck -y /dev/sda1 2) resize2fs /dev/sda1 3) reboot",
        "1) lsof +D / 2) echo 3 > /proc/sys/vm/drop_caches 3) rm -rf /tmp/*",
        "1) journalctl -u systemd-journald 2) truncate -s 0 /var/log/messages 3) sync"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking inode usage with `df -i`, (2) identifying directories consuming the most inodes, and (3) deleting unnecessary files to free up inodes.",
      "examTip": "Use `tune2fs -l /dev/sda1 | grep Inode` to check inode settings on ext filesystems."
    },
    {
      "id": 98,
      "question": "A system administrator needs to enable logging of all executed commands for auditing purposes. Which file should they modify?",
      "options": [
        "/etc/bash.bashrc",
        "/etc/audit/rules.d/audit.rules",
        "/etc/sudoers",
        "/etc/crontab"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Modifying `/etc/audit/rules.d/audit.rules` enables command logging via auditd. `bash.bashrc` can log commands but is user-specific, `sudoers` configures privilege escalation, and `crontab` schedules jobs but does not log command execution.",
      "examTip": "Use `ausearch -m EXECVE` to review logged command execution."
    },
    {
      "id": 99,
      "question": "A Linux administrator needs to troubleshoot a storage device that is showing frequent I/O errors. Which command should they use to diagnose the issue?",
      "options": [
        "smartctl -H /dev/sdX",
        "blkid /dev/sdX",
        "df -h /dev/sdX",
        "fdisk -l /dev/sdX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`smartctl -H /dev/sdX` retrieves SMART health data to check for impending drive failures. `blkid` shows partition attributes, `df -h` reports disk space usage, and `fdisk -l` lists partitions but does not diagnose hardware issues.",
      "examTip": "Use `smartctl -t long /dev/sdX` to run a detailed disk health test."
    },
    {
      "id": 100,
      "question": "Which of the following commands will verify the integrity of installed packages on a Debian-based system?",
      "options": [
        "debsums -c",
        "dpkg -l",
        "apt list --installed",
        "dpkg --configure -a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`debsums -c` checks the integrity of installed Debian packages. `dpkg -l` lists installed packages but does not verify them, `apt list --installed` shows package details but does not check integrity, and `dpkg --configure -a` attempts to fix broken installations but does not verify package integrity.",
      "examTip": "Use `debsums -s` to verify package integrity without reporting missing files."
    }
  ]
});
