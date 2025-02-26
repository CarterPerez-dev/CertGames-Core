db.tests.insertOne({
  "category": "linuxplus",
  "testId": 4,
  "testName": "Linux+ Practice Test #4 (Moderate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which command would BEST verify if a remote host (192.168.1.10) is reachable over the network?",
      "options": [
        "ping -c 4 192.168.1.10",
        "traceroute 192.168.1.10",
        "nc -zv 192.168.1.10 22",
        "arp -a 192.168.1.10"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ping -c 4` sends four ICMP echo requests to test connectivity. `traceroute` maps the route but does not confirm reachability, `nc -zv` checks open ports, and `arp -a` shows ARP cache but does not verify connectivity.",
      "examTip": "Use `ping` first to test basic connectivity before troubleshooting further with `traceroute`."
    },
    {
      "id": 2,
      "question": "A user reports they cannot resolve domain names but can access websites using IP addresses. Which file should be checked first?",
      "options": [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/network/interfaces"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/resolv.conf` contains DNS resolver settings. If misconfigured, domain name resolution will fail. `/etc/hosts` is for static hostname mapping, `/etc/nsswitch.conf` defines resolution order, and `/etc/network/interfaces` configures networking but does not directly affect DNS.",
      "examTip": "Use `cat /etc/resolv.conf` to check configured nameservers."
    },
    {
      "id": 3,
      "question": "A system administrator needs to analyze high CPU usage and terminate the problematic process. What is the correct sequence of actions?",
      "options": [
        "1) top 2) ps aux | grep <process> 3) kill -9 <PID>",
        "1) htop 2) pkill <process> 3) systemctl restart service",
        "1) ps -eo pid,%cpu,command --sort=-%cpu | head -5 2) kill -9 <PID> 3) renice -n 10 <PID>",
        "1) vmstat 2) ps -ef | grep <process> 3) kill -15 <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is to use `top` for real-time monitoring, `ps aux` to locate the exact process, and `kill -9` to forcefully terminate it. Other sequences involve incorrect steps, such as using `pkill` before verifying the process ID.",
      "examTip": "Always try `kill -15` first before resorting to `kill -9` to allow cleanup."
    },
    {
      "id": 4,
      "question": "A system administrator wants to verify if the `apache2` service is running. Which command should they use?",
      "options": [
        "systemctl status apache2",
        "service apache2 status",
        "ps aux | grep apache2",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All options can check if `apache2` is running. `systemctl status apache2` is the preferred command for systemd-based systems, `service apache2 status` works on older init systems, and `ps aux | grep apache2` searches for running processes.",
      "examTip": "Use `systemctl is-active apache2` for a quick check if a service is running."
    },
    {
      "id": 5,
      "question": "Which of the following commands will change the group ownership of a file named `report.txt` to `admins`?",
      "options": [
        "chown :admins report.txt",
        "chmod g+rw report.txt",
        "usermod -G admins report.txt",
        "setfacl -m g:admins:rwx report.txt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chown :admins report.txt` changes the group ownership. `chmod` modifies permissions, `usermod -G` manages user groups, and `setfacl` grants additional permissions but does not change ownership.",
      "examTip": "Use `ls -l report.txt` to verify ownership changes."
    },
    {
      "id": 6,
      "question": "Which of the following files is responsible for defining the default kernel parameters at boot?",
      "options": [
        "/etc/sysctl.conf",
        "/boot/grub/grub.cfg",
        "/etc/default/grub",
        "/proc/sys/kernel"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`/etc/default/grub` defines GRUB kernel parameters at boot. `/etc/sysctl.conf` manages runtime kernel parameters, `/boot/grub/grub.cfg` is auto-generated, and `/proc/sys/kernel` applies changes dynamically but does not persist.",
      "examTip": "After modifying `/etc/default/grub`, run `update-grub` to apply changes."
    },
    {
      "id": 7,
      "question": "A Linux administrator needs to check the available disk space on all mounted filesystems. Which command should they use?",
      "options": [
        "df -h",
        "du -sh /",
        "lsblk",
        "fdisk -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`df -h` displays available disk space in human-readable format. `du -sh` shows usage for a specific directory, `lsblk` lists block devices, and `fdisk -l` shows partition details but not free space.",
      "examTip": "Use `df -Th` to include filesystem types in the output."
    },
    {
      "id": 8,
      "question": "Which command will show all running processes along with their CPU and memory usage?",
      "options": [
        "top",
        "ps aux",
        "htop",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands display process details. `top` provides a real-time view, `ps aux` shows all processes, and `htop` is an interactive alternative.",
      "examTip": "Use `htop` for an interactive and user-friendly process monitoring tool."
    },
    {
      "id": 9,
      "question": "Which command would be used to identify which process is listening on port 8080?",
      "options": [
        "ss -tunlp | grep 8080",
        "netstat -tulnp | grep 8080",
        "lsof -i :8080",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can identify the process listening on port 8080. `ss` is the modern alternative to `netstat`, while `lsof -i :8080` provides process details.",
      "examTip": "Use `ss -tunap` for a full list of listening services with associated processes."
    },
    {
      "id": 10,
      "question": "Which command will display system uptime along with the number of logged-in users?",
      "options": [
        "uptime",
        "w",
        "who -b",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`uptime` displays system uptime and the number of logged-in users. `w` provides additional session details, `who -b` shows the last reboot time, and `top` includes uptime but is not its primary purpose.",
      "examTip": "Use `who` to list all currently logged-in users."
    },
    {
      "id": 11,
      "question": "Which command will display all network interfaces along with their assigned IP addresses?",
      "options": [
        "ip addr show",
        "ifconfig -a",
        "nmcli device show",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip addr show` is the modern command for displaying network interfaces and IPs. `ifconfig -a` works on older systems, and `nmcli device show` provides information for NetworkManager-managed interfaces.",
      "examTip": "Use `ip -c a` for colorized output that improves readability."
    },
    {
      "id": 12,
      "question": "Which file stores password expiration policies for all users on a Linux system?",
      "options": [
        "/etc/login.defs",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/security/pwquality.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/login.defs` defines global password aging policies. `/etc/shadow` contains hashed passwords, `/etc/passwd` stores user account details, and `/etc/security/pwquality.conf` enforces password complexity rules.",
      "examTip": "Use `chage -l <username>` to check an individual user’s password expiration details."
    },
    {
      "id": 13,
      "question": "A Linux administrator needs to troubleshoot a failing systemd service. What is the correct sequence of actions?",
      "options": [
        "1) systemctl status <service> 2) journalctl -u <service> 3) systemctl restart <service>",
        "1) ps aux | grep <service> 2) systemctl start <service> 3) reboot",
        "1) systemctl stop <service> 2) rm -rf /etc/systemd/system/<service>.service 3) systemctl daemon-reload",
        "1) tail -f /var/log/syslog 2) systemctl enable <service> 3) systemctl restart <service>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct troubleshooting approach is (1) checking service status, (2) reviewing logs with `journalctl`, and (3) restarting the service if no issues are found. Other options contain incorrect or destructive steps.",
      "examTip": "Use `systemctl restart` only if `status` and `journalctl` do not reveal errors."
    },
    {
      "id": 14,
      "question": "Which command will create a new Logical Volume (LV) named `data` with a size of 20GB inside the volume group `vg01`?",
      "options": [
        "lvcreate -L 20G -n data vg01",
        "vgcreate vg01 data 20G",
        "pvcreate /dev/sdb1",
        "mkfs.ext4 /dev/vg01/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lvcreate -L 20G -n data vg01` creates a new logical volume. `vgcreate` creates a volume group, `pvcreate` initializes a physical volume, and `mkfs.ext4` formats an existing logical volume.",
      "examTip": "Use `lvextend -L +10G /dev/vg01/data` to expand an existing logical volume."
    },
    {
      "id": 15,
      "question": "Which of the following tools is used for persistent static IP configuration on a system using NetworkManager?",
      "options": [
        "nmcli con mod <connection> ipv4.address <IP>",
        "ifconfig <interface> <IP>",
        "ip addr add <IP>/<mask> dev <interface>",
        "netplan apply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nmcli con mod <connection> ipv4.address <IP>` is the correct way to configure a persistent static IP for a NetworkManager-managed system. Other options set temporary addresses.",
      "examTip": "Use `nmcli con show` to list active network connections before modifying them."
    },
    {
      "id": 16,
      "question": "Which of the following commands will display the last 50 lines of a log file and continuously update as new lines are added?",
      "options": [
        "tail -n 50 -f /var/log/syslog",
        "head -n 50 /var/log/syslog",
        "less +F /var/log/syslog",
        "cat /var/log/syslog | tail -n 50"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tail -n 50 -f` displays the last 50 lines and continues showing new lines. `head -n 50` only displays the first 50 lines, `less +F` follows a file but behaves differently, and `cat | tail` is inefficient.",
      "examTip": "Use `journalctl -f` for real-time log monitoring on systemd-based systems."
    },
    {
      "id": 17,
      "question": "Which command will display a tree-like view of running processes?",
      "options": [
        "pstree",
        "ps aux",
        "htop",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pstree` shows processes in a hierarchical tree format. `ps aux` lists processes in a flat format, while `htop` and `top` provide real-time monitoring but do not display process trees.",
      "examTip": "Use `pstree -p` to include process IDs in the output."
    },
    {
      "id": 18,
      "question": "Which file should be modified to configure system-wide environment variables on a Linux system?",
      "options": [
        "/etc/environment",
        "/etc/profile",
        "~/.bashrc",
        "/etc/bashrc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/environment` is the correct file for setting system-wide environment variables. `/etc/profile` and `/etc/bashrc` affect login and interactive shells but do not persist across all environments.",
      "examTip": "Use `source /etc/environment` to apply changes without rebooting."
    },
    {
      "id": 19,
      "question": "Which command will recursively change the ownership of all files in `/var/www` to the `webadmin` user and group?",
      "options": [
        "chown -R webadmin:webadmin /var/www",
        "chmod -R 755 /var/www",
        "usermod -R webadmin /var/www",
        "groupadd webadmin /var/www"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chown -R webadmin:webadmin /var/www` changes ownership recursively. `chmod` modifies permissions, `usermod` does not affect file ownership, and `groupadd` creates groups, not ownership changes.",
      "examTip": "Use `ls -l /var/www` to verify ownership changes."
    },
    {
      "id": 20,
      "question": "Which command displays the default target in a systemd-based Linux distribution?",
      "options": [
        "systemctl get-default",
        "runlevel",
        "who -r",
        "systemctl list-units --type=target"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl get-default` shows the system’s default target in systemd-based distributions. `runlevel` and `who -r` apply to SysVinit, while `list-units --type=target` lists all targets but does not show the default.",
      "examTip": "Use `systemctl set-default <target>` to change the default boot target."
    },
    {
      "id": 21,
      "question": "A system administrator needs to display all open network connections and listening ports. Which command should they use?",
      "options": [
        "ss -tunap",
        "netstat -tulnp",
        "lsof -i",
        "ss -tunap | grep LISTEN"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`ss -tunap | grep LISTEN` filters the output to show only listening ports. `ss -tunap` lists all network sockets, `netstat -tulnp` works but is deprecated, and `lsof -i` lists network-related file descriptors.",
      "examTip": "Use `ss` instead of `netstat`, as `netstat` is deprecated in modern Linux systems."
    },
    {
      "id": 22,
      "question": "Which command will list all user accounts on a Linux system?",
      "options": [
        "cut -d: -f1 /etc/passwd",
        "getent passwd",
        "awk -F: '{print $1}' /etc/passwd",
        "getent group"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`getent passwd` queries the system’s account database, including `/etc/passwd` and external sources like LDAP. `cut` and `awk` extract usernames from `/etc/passwd`, but `getent` provides a more complete listing. `getent group` lists groups, not users.",
      "examTip": "Use `getent passwd | grep username` to verify if a specific user exists."
    },
    {
      "id": 23,
      "question": "A Linux administrator needs to investigate a failed SSH connection. What is the correct sequence of actions?",
      "options": [
        "1) ping <remote_host> 2) telnet <remote_host> 22 3) journalctl -u sshd",
        "1) systemctl restart sshd 2) netstat -tulnp | grep 22 3) tail -f /var/log/auth.log",
        "1) ss -tunap | grep 22 2) journalctl -u sshd 3) systemctl restart sshd",
        "1) traceroute <remote_host> 2) systemctl enable sshd 3) systemctl restart sshd"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The best approach is (1) checking if SSH is listening with `ss -tunap`, (2) reviewing logs for errors using `journalctl -u sshd`, and (3) restarting SSH if needed. Other options include incorrect or unnecessary steps.",
      "examTip": "Use `systemctl restart sshd` only after identifying the issue in logs."
    },
    {
      "id": 24,
      "question": "Which of the following commands will display all scheduled systemd timers?",
      "options": [
        "systemctl list-timers",
        "crontab -l",
        "atq",
        "ls /etc/systemd/system/*.timer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-timers` lists all scheduled systemd timers. `crontab -l` lists cron jobs, `atq` shows pending `at` jobs, and `ls /etc/systemd/system/*.timer` lists timers but does not display schedule details.",
      "examTip": "Use `systemctl list-timers --all` to include inactive timers."
    },
    {
      "id": 25,
      "question": "Which command will display the UUID and filesystem type of a given partition?",
      "options": [
        "blkid",
        "lsblk -f",
        "df -T",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`lsblk -f` shows UUIDs and filesystem types for block devices. `blkid` also retrieves UUIDs but may require root access. `df -T` shows filesystem types but not UUIDs.",
      "examTip": "Use `lsblk -o NAME,FSTYPE,UUID` for a custom-formatted output."
    },
    {
      "id": 26,
      "question": "Which file should be modified to configure static DNS settings on a Linux system?",
      "options": [
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/network/interfaces",
        "/etc/hosts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/resolv.conf` contains DNS settings. `/etc/nsswitch.conf` defines lookup order, `/etc/network/interfaces` configures network settings on Debian-based systems, and `/etc/hosts` maps static hostnames to IPs.",
      "examTip": "Use `chattr +i /etc/resolv.conf` to prevent changes if overwritten by DHCP."
    },
    {
      "id": 27,
      "question": "Which command will display the last 100 lines of a log file and continue following updates in real-time?",
      "options": [
        "tail -n 100 -f /var/log/syslog",
        "head -n 100 /var/log/syslog",
        "less +F /var/log/syslog",
        "cat /var/log/syslog | tail -n 100"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tail -n 100 -f` displays the last 100 lines and continues updating in real time. `head -n 100` shows only the first 100 lines, `less +F` follows a file but behaves differently, and `cat | tail` is inefficient.",
      "examTip": "Use `journalctl -f` for live logs in systemd-based systems."
    },
    {
      "id": 28,
      "question": "Which command will show the kernel version currently running on a Linux system?",
      "options": [
        "uname -r",
        "cat /proc/version",
        "lsb_release -a",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`uname -r` is the preferred command for checking the running kernel version. `/proc/version` contains additional details, and `lsb_release -a` shows distribution information but not the kernel version.",
      "examTip": "Use `uname -a` to see additional system information such as architecture and hostname."
    },
    {
      "id": 29,
      "question": "Which command will display all active SSH sessions on a Linux server?",
      "options": [
        "who",
        "ss -tunap | grep ssh",
        "w",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide information about active SSH sessions. `who` and `w` list logged-in users, while `ss -tunap | grep ssh` shows active SSH connections.",
      "examTip": "Use `last -a | grep still` to find users still logged in."
    },
    {
      "id": 30,
      "question": "Which command will reload the Udev rules without rebooting the system?",
      "options": [
        "udevadm control --reload-rules",
        "systemctl restart udev",
        "modprobe -r udev && modprobe udev",
        "service udev reload"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`udevadm control --reload-rules` applies changes to Udev rules immediately. Restarting Udev is not always necessary, `modprobe` manages kernel modules, and `service` is deprecated.",
      "examTip": "Run `udevadm trigger` after reloading rules to apply changes immediately."
    },
    {
      "id": 31,
      "question": "Which command will safely unmount a busy filesystem located at `/mnt/data`?",
      "options": [
        "umount -l /mnt/data",
        "unmount /mnt/data",
        "fuser -k /mnt/data",
        "rm -rf /mnt/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`umount -l` (lazy unmount) detaches a busy filesystem, allowing processes to close their references before unmounting. `unmount` is not a valid command, `fuser -k` kills processes but does not unmount, and `rm -rf` deletes files but does not unmount.",
      "examTip": "Use `lsof +D /mnt/data` to check which processes are using the mount before unmounting."
    },
    {
      "id": 32,
      "question": "Which command will list all failed systemd services?",
      "options": [
        "systemctl --failed",
        "systemctl list-units --state=failed",
        "journalctl -p err",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`systemctl list-units --state=failed` explicitly lists failed services. `systemctl --failed` provides a summary, while `journalctl -p err` shows errors but not necessarily failed services.",
      "examTip": "Use `journalctl -u <service>` to check logs for a specific failed service."
    },
    {
      "id": 33,
      "question": "A system administrator needs to create a new Logical Volume and extend it later. What is the correct sequence of actions?",
      "options": [
        "1) pvcreate /dev/sdb1 2) vgcreate vg01 /dev/sdb1 3) lvcreate -L 10G -n lv_data vg01 4) lvextend -L +5G /dev/vg01/lv_data",
        "1) vgcreate vg01 /dev/sdb1 2) pvcreate /dev/sdb1 3) lvcreate -L 10G -n lv_data vg01 4) lvextend -L +5G /dev/vg01/lv_data",
        "1) lvcreate -L 10G -n lv_data vg01 2) pvcreate /dev/sdb1 3) vgcreate vg01 /dev/sdb1 4) lvextend -L +5G /dev/vg01/lv_data",
        "1) lvextend -L +5G /dev/vg01/lv_data 2) pvcreate /dev/sdb1 3) vgcreate vg01 /dev/sdb1 4) lvcreate -L 10G -n lv_data vg01"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct sequence is: (1) initialize the disk with `pvcreate`, (2) create a volume group with `vgcreate`, (3) create a logical volume with `lvcreate`, and (4) extend it with `lvextend` as needed.",
      "examTip": "Use `lvextend --resizefs` to extend both the volume and filesystem in one step."
    },
    {
      "id": 34,
      "question": "Which command will show the system’s default gateway?",
      "options": [
        "ip route show default",
        "netstat -rn",
        "route -n",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip route show default` is the modern way to check the system’s default gateway. `netstat -rn` and `route -n` also work but are older methods.",
      "examTip": "Use `ip route get 8.8.8.8` to check which gateway is used for a specific destination."
    },
    {
      "id": 35,
      "question": "A system administrator needs to delete a user account along with the home directory. Which command should they use?",
      "options": [
        "userdel -r <username>",
        "deluser --remove-home <username>",
        "rm -rf /home/<username>",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`deluser --remove-home <username>` safely removes a user and its home directory. `userdel -r` does the same on some distributions but may not be available. `rm -rf` deletes files but does not remove the user account.",
      "examTip": "Use `cat /etc/passwd | grep <username>` to verify if an account still exists after deletion."
    },
    {
      "id": 36,
      "question": "Which command will display the default umask value for new files?",
      "options": [
        "umask",
        "cat /etc/login.defs | grep UMASK",
        "echo $UMASK",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`cat /etc/login.defs | grep UMASK` shows the system-wide default `umask`. Running `umask` shows the current session’s value but not system defaults. `$UMASK` is not a standard variable.",
      "examTip": "Default `umask` is usually `022`, giving `755` for directories and `644` for files."
    },
    {
      "id": 37,
      "question": "Which command is used to securely delete a file by overwriting its contents?",
      "options": [
        "shred",
        "rm -f",
        "unlink",
        "mv /dev/null"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`shred` securely overwrites file contents before deletion. `rm -f` removes files without confirmation, `unlink` deletes a single file, and `mv /dev/null` is incorrect syntax.",
      "examTip": "Use `shred -n 3 -z filename` to overwrite a file multiple times before deleting."
    },
    {
      "id": 38,
      "question": "Which command allows a user to execute commands as another user without switching sessions?",
      "options": [
        "sudo",
        "su -",
        "pkexec",
        "All of the above"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`pkexec` allows users to run commands as another user in a graphical or CLI environment. `sudo` is the standard way for privileged execution, and `su -` switches to another user’s session.",
      "examTip": "Use `sudo -u <user> <command>` to execute as another user without switching sessions."
    },
    {
      "id": 39,
      "question": "Which command displays disk I/O statistics in real time?",
      "options": [
        "iostat",
        "vmstat",
        "iotop",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide disk I/O statistics. `iostat` shows per-device stats, `vmstat` provides system-wide performance metrics, and `iotop` shows real-time per-process disk activity.",
      "examTip": "Use `iotop -o` to filter only processes currently writing to disk."
    },
    {
      "id": 40,
      "question": "Which command will reload SSH configuration changes without disconnecting active users?",
      "options": [
        "systemctl reload sshd",
        "systemctl restart sshd",
        "kill -HUP $(pidof sshd)",
        "service sshd restart"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl reload sshd` applies configuration changes without disconnecting users. `restart` would terminate active sessions, and `kill -HUP` is an alternative but not the recommended method.",
      "examTip": "Use `sshd -t` to test `sshd_config` before reloading to avoid syntax errors."
    },
    {
      "id": 41,
      "question": "A user reports that they cannot write to a file despite being its owner. What is the MOST likely cause?",
      "options": [
        "The file has the immutable attribute set.",
        "The user does not have execute permissions on the directory.",
        "The file is owned by another user.",
        "The filesystem is mounted as read-only."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If a file has the immutable attribute (`chattr +i`), even the owner cannot modify it. Lack of execute permissions on a directory prevents navigation, not file modification. Ownership issues do not matter if permissions allow writing, and a read-only filesystem would affect all files, not just one.",
      "examTip": "Use `lsattr filename` to check for immutable attributes before troubleshooting further."
    },
    {
      "id": 42,
      "question": "Which command displays the most detailed CPU utilization statistics, including per-core usage?",
      "options": [
        "mpstat -P ALL",
        "top",
        "lscpu",
        "cat /proc/cpuinfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`mpstat -P ALL` provides per-core CPU usage statistics. `top` shows real-time CPU activity, `lscpu` provides architecture details, and `/proc/cpuinfo` lists hardware specifications but does not monitor usage.",
      "examTip": "Install `sysstat` to use `mpstat` for detailed CPU analysis."
    },
    {
      "id": 43,
      "question": "A Linux administrator needs to investigate high memory usage and free up system resources. What is the correct sequence of actions?",
      "options": [
        "1) free -m 2) ps aux --sort=-%mem 3) kill <PID>",
        "1) vmstat 1 5 2) swapoff -a 3) reboot",
        "1) top 2) pkill -9 <process> 3) echo 3 > /proc/sys/vm/drop_caches",
        "1) htop 2) kill -15 <PID> 3) echo 1 > /proc/sys/vm/drop_caches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best sequence is (1) checking memory with `free -m`, (2) identifying memory-consuming processes with `ps aux --sort=-%mem`, and (3) terminating unnecessary processes with `kill <PID>`. Other sequences contain risky or unnecessary steps.",
      "examTip": "Use `kill -15` before `kill -9` to allow processes to exit cleanly."
    },
    {
      "id": 44,
      "question": "Which of the following commands will remove a software package along with its configuration files on a Debian-based system?",
      "options": [
        "apt-get purge <package>",
        "apt-get remove <package>",
        "dpkg -r <package>",
        "dpkg --purge <package>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`apt-get purge` removes both the package and its configuration files. `apt-get remove` deletes only the package, `dpkg -r` removes a package but leaves config files, and `dpkg --purge` achieves the same as `apt-get purge` but is less commonly used.",
      "examTip": "Run `dpkg -l | grep <package>` to check if a package is installed before removing it."
    },
    {
      "id": 45,
      "question": "Which command will modify the default permissions for newly created files and directories?",
      "options": [
        "umask",
        "chmod",
        "setfacl",
        "chown"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`umask` sets default permissions for new files and directories in a session. `chmod` modifies existing file permissions, `setfacl` manages ACLs, and `chown` changes file ownership.",
      "examTip": "Use `umask 002` for shared directories where all users in a group need write access."
    },
    {
      "id": 46,
      "question": "Which command will show all processes running as user `apache`?",
      "options": [
        "ps -u apache",
        "top -u apache",
        "pgrep -u apache",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All commands can show processes running as `apache`. `ps -u apache` lists processes by user, `top -u apache` shows real-time usage, and `pgrep -u apache` lists PIDs.",
      "examTip": "Use `ps -eo user,pid,%cpu,%mem,command | grep apache` for more detailed filtering."
    },
    {
      "id": 47,
      "question": "Which command will display all users currently logged into the system?",
      "options": [
        "w",
        "who",
        "users",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide details about logged-in users. `w` shows user activity, `who` lists user sessions, and `users` prints a simple list of logged-in usernames.",
      "examTip": "Use `last` to see a history of user logins."
    },
    {
      "id": 48,
      "question": "A user is unable to execute a script due to permission issues. Which command will grant execute permissions?",
      "options": [
        "chmod +x script.sh",
        "chown user:user script.sh",
        "chmod 644 script.sh",
        "ls -l script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chmod +x script.sh` grants execute permissions. `chown` changes ownership but does not modify permissions, `chmod 644` sets read/write permissions but does not allow execution, and `ls -l` only displays permissions.",
      "examTip": "Use `ls -l script.sh` to check current permissions before modifying them."
    },
    {
      "id": 49,
      "question": "Which command will display a hierarchical view of running processes?",
      "options": [
        "pstree",
        "ps aux",
        "htop",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pstree` displays processes in a tree format, showing parent-child relationships. `ps aux` lists processes in a flat view, and `htop`/`top` provide real-time monitoring but do not display process hierarchies.",
      "examTip": "Use `pstree -p` to include process IDs in the output."
    },
    {
      "id": 50,
      "question": "Which command will list all active listening ports on a Linux system?",
      "options": [
        "ss -tuln",
        "netstat -tulnp",
        "lsof -i -P -n",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ss -tuln` lists all active listening ports and is the modern replacement for `netstat -tulnp`. `lsof -i -P -n` provides similar information but includes active connections.",
      "examTip": "Use `ss -tunap` to include process names associated with network sockets."
    },
    {
      "id": 51,
      "question": "Which command will display the total amount of free and used physical memory on a Linux system?",
      "options": [
        "free -h",
        "vmstat -s",
        "top",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide memory usage details. `free -h` shows a human-readable format, `vmstat -s` provides system-wide memory statistics, and `top` includes real-time memory usage.",
      "examTip": "Use `free -m` to display memory usage in megabytes."
    },
    {
      "id": 52,
      "question": "Which command will display the last system boot time?",
      "options": [
        "who -b",
        "uptime",
        "last reboot",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`who -b` specifically shows the last system boot time. `uptime` shows how long the system has been running, and `last reboot` lists historical reboots.",
      "examTip": "Use `journalctl -b` to see logs from the most recent boot."
    },
    {
      "id": 53,
      "question": "A system administrator needs to restore network connectivity after an interface fails. What is the correct sequence of actions?",
      "options": [
        "1) ip link set eth0 down 2) ip link set eth0 up 3) dhclient eth0",
        "1) systemctl restart network 2) ip a 3) ping 8.8.8.8",
        "1) nmcli con down eth0 2) nmcli con up eth0 3) ip route show",
        "1) netstat -rn 2) ifdown eth0 3) ifup eth0"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) bringing the interface down, (2) bringing it back up, and (3) requesting an IP via DHCP. Other sequences either skip DHCP renewal or use deprecated commands.",
      "examTip": "Use `ip a` to check if an interface has a valid IP after bringing it up."
    },
    {
      "id": 54,
      "question": "Which command will permanently set the hostname on a system using systemd?",
      "options": [
        "hostnamectl set-hostname <new_hostname>",
        "echo <new_hostname> > /etc/hostname",
        "sysctl kernel.hostname=<new_hostname>",
        "hostname <new_hostname>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`hostnamectl set-hostname <new_hostname>` is the correct way to set the hostname permanently on systemd systems. Editing `/etc/hostname` works but requires a reboot, `sysctl` changes the hostname temporarily, and `hostname` affects only the current session.",
      "examTip": "Use `hostnamectl status` to verify the current hostname setting."
    },
    {
      "id": 55,
      "question": "Which command will display the default runlevel (target) for a systemd-based Linux system?",
      "options": [
        "systemctl get-default",
        "runlevel",
        "who -r",
        "systemctl list-units --type=target"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl get-default` shows the system’s default target in systemd-based distributions. `runlevel` and `who -r` apply to SysVinit systems, while `systemctl list-units --type=target` lists available targets but does not show the default.",
      "examTip": "Use `systemctl set-default <target>` to change the default boot target."
    },
    {
      "id": 56,
      "question": "Which command is used to modify the password aging policy for a user?",
      "options": [
        "chage",
        "passwd",
        "usermod",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chage` is specifically designed for modifying password aging policies. `passwd` can change a password but does not modify expiration settings, and `usermod` can modify user attributes but not password aging.",
      "examTip": "Use `chage -l <username>` to check an individual user’s password expiration details."
    },
    {
      "id": 57,
      "question": "Which file stores the bootloader configuration for GRUB2?",
      "options": [
        "/boot/grub/grub.cfg",
        "/etc/default/grub",
        "/etc/grub.d/40_custom",
        "/boot/efi/EFI/grub.cfg"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`/etc/default/grub` is the correct file for modifying GRUB2 settings. `/boot/grub/grub.cfg` is generated based on `/etc/default/grub`, while `/etc/grub.d/40_custom` allows custom menu entries.",
      "examTip": "Run `grub2-mkconfig -o /boot/grub2/grub.cfg` after modifying `/etc/default/grub`."
    },
    {
      "id": 58,
      "question": "Which command will list all systemd services along with their current states?",
      "options": [
        "systemctl list-units --type=service",
        "systemctl list-services",
        "systemctl list-running",
        "service --status-all"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=service` lists all systemd services with their statuses. `systemctl list-services` is not a valid command, `systemctl list-running` shows only active services, and `service --status-all` applies to SysVinit systems.",
      "examTip": "Use `systemctl --failed` to list only failed services."
    },
    {
      "id": 59,
      "question": "Which command will allow a user to execute commands as another user without switching sessions?",
      "options": [
        "sudo",
        "su -",
        "pkexec",
        "All of the above"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`pkexec` allows users to run commands as another user in a graphical or CLI environment. `sudo` is the standard way for privileged execution, and `su -` switches to another user’s session.",
      "examTip": "Use `sudo -u <user> <command>` to execute as another user without switching sessions."
    },
    {
      "id": 60,
      "question": "Which command allows a system administrator to analyze disk usage and identify the largest directories?",
      "options": [
        "du -sh /* | sort -hr",
        "df -h",
        "ls -lhS /",
        "stat /"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh /* | sort -hr` lists all top-level directories and sorts them by size. `df -h` shows filesystem usage but not per-directory size, `ls -lhS` sorts by file size but does not summarize directories, and `stat /` shows metadata.",
      "examTip": "Use `du -sh /path/* | sort -hr` to quickly find the largest directories."
    },
    {
      "id": 61,
      "question": "Which of the following commands will display the UUIDs of all block devices?",
      "options": [
        "blkid",
        "lsblk -f",
        "df -T",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`blkid` retrieves the UUIDs of all block devices. `lsblk -f` provides filesystem types but may not always show UUIDs, `df -T` lists filesystem types but does not display UUIDs, and `mount -l` lists mounted filesystems.",
      "examTip": "Use `blkid | grep UUID` to filter results specifically for UUIDs."
    },
    {
      "id": 62,
      "question": "Which command is used to configure a persistent static IP address on a system using NetworkManager?",
      "options": [
        "nmcli con mod <connection> ipv4.address <IP>",
        "ifconfig <interface> <IP>",
        "ip addr add <IP>/<mask> dev <interface>",
        "netplan apply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nmcli con mod <connection> ipv4.address <IP>` is the correct command for configuring a persistent static IP on a system using NetworkManager. `ifconfig` and `ip addr add` set temporary addresses, while `netplan apply` is used in Ubuntu-based systems.",
      "examTip": "Use `nmcli con show` to list active network connections before modifying them."
    },
    {
      "id": 63,
      "question": "A Linux administrator needs to investigate a failing service that is not starting. What is the correct sequence of actions?",
      "options": [
        "1) systemctl status <service> 2) journalctl -u <service> 3) systemctl restart <service>",
        "1) systemctl restart <service> 2) ps aux | grep <service> 3) journalctl -u <service>",
        "1) tail -f /var/log/syslog 2) systemctl enable <service> 3) systemctl restart <service>",
        "1) systemctl stop <service> 2) systemctl disable <service> 3) rm -rf /etc/systemd/system/<service>.service"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking service status, (2) reviewing logs with `journalctl -u <service>`, and (3) restarting the service if no issues are found. Other options contain incorrect or destructive steps.",
      "examTip": "Use `systemctl restart` only if `status` and `journalctl` do not reveal errors."
    },
    {
      "id": 64,
      "question": "Which file is responsible for defining persistent static hostname settings on a Linux system?",
      "options": [
        "/etc/hostname",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/sysconfig/network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/hostname` stores the system’s persistent hostname, which is read at boot. `/etc/hosts` is for static hostname-to-IP mappings, `/etc/resolv.conf` defines DNS resolvers, and `/etc/sysconfig/network` is used on older Red Hat-based systems.",
      "examTip": "Use `hostnamectl set-hostname <new_hostname>` to change the hostname on systemd-based systems."
    },
    {
      "id": 65,
      "question": "Which command allows an administrator to check user password expiration details?",
      "options": [
        "chage -l <username>",
        "passwd -S <username>",
        "cat /etc/shadow",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chage -l <username>` displays detailed password expiration settings. `passwd -S` provides a summary, and `/etc/shadow` contains expiration details but requires manual parsing.",
      "examTip": "Use `chage -E <date> <username>` to set an account expiration date."
    },
    {
      "id": 66,
      "question": "Which of the following commands will reload SSH configuration changes without disconnecting active users?",
      "options": [
        "systemctl reload sshd",
        "systemctl restart sshd",
        "kill -HUP $(pidof sshd)",
        "service sshd restart"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl reload sshd` applies changes to `sshd_config` without disconnecting active users. `restart` would terminate sessions, `kill -HUP` is a lower-level alternative, and `service sshd restart` is deprecated.",
      "examTip": "Use `sshd -t` before reloading to verify that configuration changes are valid."
    },
    {
      "id": 67,
      "question": "Which command allows a user to execute commands as another user without switching to their session?",
      "options": [
        "sudo -u <user> <command>",
        "su <user> -c <command>",
        "pkexec <command>",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands allow executing commands as another user without switching to their session. `sudo -u` runs a command as another user, `su -c` executes commands as another user, and `pkexec` provides an alternative.",
      "examTip": "Use `sudo -u <user> -s` to open a shell as another user."
    },
    {
      "id": 68,
      "question": "Which command will display the disk usage of a specific directory and its subdirectories?",
      "options": [
        "du -sh /path/to/directory",
        "df -h /path/to/directory",
        "ls -lhS /path/to/directory",
        "stat /path/to/directory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh` shows the total size of a directory and its contents. `df -h` reports filesystem usage, `ls -lhS` sorts by file size but does not sum directory sizes, and `stat` provides file metadata.",
      "examTip": "Use `du -sh * | sort -hr` to list the largest directories in descending order."
    },
    {
      "id": 69,
      "question": "Which command will display all failed systemd services?",
      "options": [
        "systemctl list-units --state=failed",
        "systemctl --failed",
        "journalctl -p err",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`systemctl --failed` provides a quick list of failed systemd services. `list-units --state=failed` offers more details, while `journalctl -p err` shows system logs but does not isolate failed services.",
      "examTip": "Use `journalctl -xe` for a detailed log of failed services."
    },
    {
      "id": 70,
      "question": "Which command is used to display the most recent log messages in a systemd-based system?",
      "options": [
        "journalctl -n 50",
        "dmesg",
        "tail -n 50 /var/log/syslog",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`journalctl -n 50` retrieves the last 50 log messages from the systemd journal. `dmesg` provides kernel logs, and `tail -n 50` shows syslog entries but may not include all system logs.",
      "examTip": "Use `journalctl -f` to monitor logs in real time."
    },
    {
      "id": 71,
      "question": "Which command is used to list all kernel modules currently loaded on a Linux system?",
      "options": [
        "lsmod",
        "modinfo",
        "modprobe -l",
        "depmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsmod` lists all loaded kernel modules. `modinfo` provides details about a specific module, `modprobe -l` lists available but not necessarily loaded modules, and `depmod` updates module dependencies.",
      "examTip": "Use `lsmod | grep <module>` to check if a specific module is loaded."
    },
    {
      "id": 72,
      "question": "Which command will display all active SSH sessions on a Linux server?",
      "options": [
        "who",
        "w",
        "ss -tunap | grep ssh",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide information on active SSH sessions. `who` lists logged-in users, `w` provides detailed session information, and `ss -tunap | grep ssh` shows active SSH connections.",
      "examTip": "Use `last -a | grep still` to find users still logged in."
    },
    {
      "id": 73,
      "question": "A Linux administrator needs to identify and terminate a process consuming excessive disk I/O. What is the correct sequence of actions?",
      "options": [
        "1) iotop 2) ps aux | grep <process> 3) kill <PID>",
        "1) vmstat 1 5 2) lsof -p <PID> 3) kill -9 <PID>",
        "1) top 2) renice -n 10 <PID> 3) pkill <process>",
        "1) htop 2) fuser -k <process> 3) echo 3 > /proc/sys/vm/drop_caches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) using `iotop` to monitor disk usage, (2) verifying the process with `ps aux`, and (3) terminating it with `kill <PID>`. Other sequences contain incorrect or unnecessary steps.",
      "examTip": "Use `kill -15` before `kill -9` to allow processes to exit cleanly."
    },
    {
      "id": 74,
      "question": "Which command is used to manually trigger a scheduled systemd timer?",
      "options": [
        "systemctl start <timer>.timer",
        "systemctl enable <timer>.timer",
        "systemctl daemon-reexec",
        "at now -f <timer>.timer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl start <timer>.timer` manually triggers a systemd timer immediately. `systemctl enable` ensures the timer runs on schedule, `systemctl daemon-reexec` reloads systemd but does not trigger a timer, and `at` is for one-time jobs.",
      "examTip": "Use `systemctl list-timers --all` to check scheduled timers."
    },
    {
      "id": 75,
      "question": "Which command will display all scheduled cron jobs for a specific user?",
      "options": [
        "crontab -l -u <username>",
        "crontab -e -u <username>",
        "systemctl list-timers --user <username>",
        "ls /etc/cron.d/<username>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`crontab -l -u <username>` lists scheduled cron jobs for a user. `crontab -e` opens the editor but does not list jobs, `systemctl list-timers` lists systemd timers, and `/etc/cron.d/` contains system-wide cron jobs but not user-specific ones.",
      "examTip": "Use `crontab -r -u <username>` to remove all cron jobs for a user."
    },
    {
      "id": 76,
      "question": "Which command is used to configure a default gateway on a Linux system?",
      "options": [
        "ip route add default via <gateway_ip>",
        "route add default gw <gateway_ip>",
        "netstat -rn",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip route add default via <gateway_ip>` is the modern command for setting a default gateway. `route add default gw` works on older systems, and `netstat -rn` displays the routing table but does not configure a gateway.",
      "examTip": "Use `ip route get <IP>` to check which gateway is used for a specific destination."
    },
    {
      "id": 77,
      "question": "Which command allows a user to modify kernel parameters at runtime?",
      "options": [
        "sysctl -w",
        "modprobe",
        "lsmod",
        "insmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sysctl -w` modifies kernel parameters at runtime. `modprobe` loads kernel modules, `lsmod` lists loaded modules, and `insmod` inserts modules but does not modify parameters.",
      "examTip": "To make changes persistent, add them to `/etc/sysctl.conf` and run `sysctl -p`."
    },
    {
      "id": 78,
      "question": "Which command is used to analyze detailed hardware information, including motherboard and BIOS details?",
      "options": [
        "dmidecode",
        "lscpu",
        "lsblk",
        "cat /proc/meminfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`dmidecode` retrieves hardware information such as BIOS, motherboard, and processor details. `lscpu` focuses on CPU architecture, `lsblk` lists block devices, and `/proc/meminfo` provides memory statistics but not BIOS details.",
      "examTip": "Run `sudo dmidecode -t system` for full system hardware information."
    },
    {
      "id": 79,
      "question": "Which command will display a list of open files associated with a specific process?",
      "options": [
        "lsof -p <PID>",
        "ps aux | grep <PID>",
        "netstat -nap | grep <PID>",
        "fdisk -l <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof -p <PID>` lists all open files associated with a specific process. `ps aux` shows process details but not open files, `netstat` displays network sockets, and `fdisk` is unrelated to processes.",
      "examTip": "Use `lsof +D /path/to/directory` to find all files open in a directory."
    },
    {
      "id": 80,
      "question": "Which command is used to modify an existing user’s primary group?",
      "options": [
        "usermod -g <group> <user>",
        "groupmod -g <group> <user>",
        "chgrp <group> <user>",
        "gpasswd -a <user> <group>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`usermod -g <group> <user>` changes a user’s primary group. `groupmod` modifies group IDs, `chgrp` changes file ownership but not user groups, and `gpasswd -a` adds a user to a secondary group, not the primary group.",
      "examTip": "Use `id <user>` to check a user’s current group memberships."
    },
    {
      "id": 81,
      "question": "Which command will display detailed CPU statistics, including per-core usage and I/O wait times?",
      "options": [
        "mpstat -P ALL",
        "top",
        "uptime",
        "cat /proc/cpuinfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`mpstat -P ALL` provides per-core CPU usage, including idle time, system time, and I/O wait percentages. `top` shows real-time CPU activity, `uptime` reports system load averages, and `/proc/cpuinfo` lists CPU details but not usage statistics.",
      "examTip": "Install `sysstat` to use `mpstat` for detailed CPU performance analysis."
    },
    {
      "id": 82,
      "question": "Which command is used to monitor real-time disk I/O usage by individual processes?",
      "options": [
        "iotop",
        "iostat",
        "vmstat",
        "df -h"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iotop` displays real-time disk I/O usage per process. `iostat` provides overall disk activity statistics, `vmstat` monitors system performance, and `df -h` shows filesystem usage, not per-process I/O.",
      "examTip": "Use `iotop -o` to show only processes actively writing to disk."
    },
    {
      "id": 83,
      "question": "A Linux administrator needs to configure a new partition for use. What is the correct sequence of actions?",
      "options": [
        "1) fdisk /dev/sdb 2) mkfs.ext4 /dev/sdb1 3) mount /dev/sdb1 /mnt/data",
        "1) mkfs.ext4 /dev/sdb 2) mount /dev/sdb /mnt/data 3) fdisk /dev/sdb",
        "1) mount /dev/sdb1 /mnt/data 2) fdisk /dev/sdb 3) mkfs.ext4 /dev/sdb1",
        "1) lvcreate -L 10G -n lv_data vg01 2) mkfs.ext4 /dev/vg01/lv_data 3) mount /dev/vg01/lv_data /mnt/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct sequence is (1) using `fdisk` to create a partition, (2) formatting it with `mkfs.ext4`, and (3) mounting it. Other sequences either mount before formatting or use incorrect partitioning methods.",
      "examTip": "Use `lsblk` to verify partitions before formatting and mounting."
    },
    {
      "id": 84,
      "question": "Which command allows a system administrator to modify an existing user’s shell?",
      "options": [
        "chsh -s /bin/bash <user>",
        "usermod -s /bin/bash <user>",
        "passwd -e <user>",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`usermod -s /bin/bash <user>` modifies a user’s default shell. `chsh -s` also works but requires the shell to be listed in `/etc/shells`. `passwd -e` forces a password change but does not modify shells.",
      "examTip": "Use `cat /etc/shells` to verify available shells before changing a user’s default shell."
    },
    {
      "id": 85,
      "question": "Which of the following firewall management tools is the default on modern Red Hat-based distributions?",
      "options": [
        "firewalld",
        "iptables",
        "nftables",
        "ufw"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`firewalld` is the default firewall tool on Red Hat-based distributions. `iptables` is older, `nftables` is newer but not always the default, and `ufw` is commonly used on Ubuntu-based systems.",
      "examTip": "Use `firewall-cmd --permanent --add-service=ssh` to allow SSH traffic permanently."
    },
    {
      "id": 86,
      "question": "Which command will list all active listening ports on a Linux system?",
      "options": [
        "ss -tuln",
        "netstat -tulnp",
        "lsof -i -P -n",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ss -tuln` lists all active listening ports and is the modern replacement for `netstat -tulnp`. `lsof -i -P -n` provides similar information but includes active connections.",
      "examTip": "Use `ss -tunap` to include process names associated with network sockets."
    },
    {
      "id": 87,
      "question": "Which of the following commands will display the default route and routing table?",
      "options": [
        "ip route show",
        "netstat -rn",
        "route -n",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can display the default route and routing table. `ip route show` is the modern method, while `netstat -rn` and `route -n` are older alternatives.",
      "examTip": "Use `ip route get <IP>` to see which route is used for a specific destination."
    },
    {
      "id": 88,
      "question": "Which command is used to modify the kernel parameters at runtime?",
      "options": [
        "sysctl -w",
        "modprobe",
        "lsmod",
        "insmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sysctl -w` modifies kernel parameters without rebooting. `modprobe` loads kernel modules, `lsmod` lists loaded modules, and `insmod` manually loads a module but does not modify parameters.",
      "examTip": "Use `sysctl -p` to apply persistent kernel parameter changes from `/etc/sysctl.conf`."
    },
    {
      "id": 89,
      "question": "Which of the following commands will display all users currently logged into the system?",
      "options": [
        "who",
        "w",
        "users",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide information about logged-in users. `who` lists session details, `w` provides additional activity information, and `users` simply lists logged-in usernames.",
      "examTip": "Use `last` to see historical login information."
    },
    {
      "id": 90,
      "question": "Which command is used to configure persistent system-wide environment variables?",
      "options": [
        "echo 'VAR=value' >> /etc/environment",
        "export VAR=value",
        "echo 'VAR=value' >> ~/.bashrc",
        "echo 'VAR=value' >> /etc/profile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Appending variables to `/etc/environment` ensures they are persistent system-wide. `export` sets variables only for the current session, and `~/.bashrc` applies only to the current user. `/etc/profile` affects interactive logins but not non-interactive shells.",
      "examTip": "Use `source /etc/environment` to apply changes without rebooting."
    },
    {
      "id": 91,
      "question": "Which command allows a user to search for a specific process by name?",
      "options": [
        "pgrep <process>",
        "ps aux | grep <process>",
        "pidof <process>",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can search for a specific process by name. `pgrep` returns process IDs, `ps aux | grep` filters process details, and `pidof` shows PIDs for running executables.",
      "examTip": "Use `pgrep -l <process>` to include process names in the output."
    },
    {
      "id": 92,
      "question": "Which file controls user password expiration policies system-wide?",
      "options": [
        "/etc/login.defs",
        "/etc/shadow",
        "/etc/security/pwquality.conf",
        "/etc/default/useradd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/login.defs` defines global password aging policies. `/etc/shadow` stores individual user expiration details, `/etc/security/pwquality.conf` enforces password complexity, and `/etc/default/useradd` defines default settings for new users.",
      "examTip": "Use `chage -l <username>` to check a user's expiration settings."
    },
    {
      "id": 93,
      "question": "A Linux administrator needs to recover a deleted file that was still open by a running process. What is the correct sequence of actions?",
      "options": [
        "1) lsof | grep deleted 2) cp /proc/<PID>/fd/<FD> /recovered_file 3) restart service",
        "1) journalctl -xe 2) lsof -p <PID> 3) rm -rf /proc/<PID>/fd/<FD>",
        "1) ps aux | grep <process> 2) umount -l /dev/sdX1 3) recover /dev/sdX1",
        "1) fuser -v /path/to/file 2) kill -9 <PID> 3) mv /proc/<PID>/fd/<FD> /recovered_file"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best method is (1) identifying the open file using `lsof`, (2) copying the deleted file from `/proc/<PID>/fd/<FD>`, and (3) restarting the service if necessary. Other sequences contain incorrect steps or data-destroying actions.",
      "examTip": "Recover open but deleted files by copying from `/proc/<PID>/fd/` before the process terminates."
    },
    {
      "id": 94,
      "question": "Which command will display the default gateway configured on a Linux system?",
      "options": [
        "ip route show default",
        "netstat -rn",
        "route -n",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip route show default` is the preferred modern command. `netstat -rn` and `route -n` also work but are older alternatives.",
      "examTip": "Use `ip route get <IP>` to see which gateway is used for a specific destination."
    },
    {
      "id": 95,
      "question": "Which command will display the current SELinux mode?",
      "options": [
        "getenforce",
        "sestatus",
        "ls -Z",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`getenforce` shows the current SELinux mode (`Enforcing`, `Permissive`, or `Disabled`). `sestatus` provides more details, and `ls -Z` lists SELinux labels but does not display the mode.",
      "examTip": "Use `sestatus` for a full report of SELinux status and policies."
    },
    {
      "id": 96,
      "question": "Which command allows a user to modify an existing group’s name?",
      "options": [
        "groupmod -n <new_group> <old_group>",
        "usermod -g <group> <user>",
        "gpasswd -a <user> <group>",
        "chgrp <group> <file>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`groupmod -n` renames an existing group. `usermod -g` changes a user’s primary group, `gpasswd -a` adds a user to a group, and `chgrp` changes file ownership but not group names.",
      "examTip": "Use `getent group` to verify group changes."
    },
    {
      "id": 97,
      "question": "Which command will display a hierarchical view of running processes?",
      "options": [
        "pstree",
        "ps aux",
        "htop",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pstree` displays processes in a tree format, showing parent-child relationships. `ps aux` lists processes in a flat format, `htop` provides real-time monitoring but does not show a tree view, and `top` focuses on CPU/memory usage.",
      "examTip": "Use `pstree -p` to include process IDs in the output."
    },
    {
      "id": 98,
      "question": "Which command will list all available services and their statuses on a systemd-based Linux system?",
      "options": [
        "systemctl list-units --type=service",
        "systemctl list-services",
        "systemctl list-running",
        "service --status-all"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=service` lists all systemd services and their statuses. `systemctl list-services` is not a valid command, `systemctl list-running` shows only active services, and `service --status-all` applies to SysVinit systems.",
      "examTip": "Use `systemctl --failed` to list only failed services."
    },
    {
      "id": 99,
      "question": "Which command will display disk usage for all directories in `/var`?",
      "options": [
        "du -sh /var/*",
        "df -h /var",
        "ls -lh /var",
        "stat /var"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh /var/*` shows the disk usage of all directories inside `/var`. `df -h` reports filesystem usage, `ls -lh` lists file sizes but does not summarize directories, and `stat` provides file metadata.",
      "examTip": "Use `du -sh * | sort -hr` to list the largest directories in descending order."
    },
    {
      "id": 100,
      "question": "Which command is used to analyze system performance by displaying real-time CPU, memory, and I/O statistics?",
      "options": [
        "vmstat",
        "top",
        "iostat",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide real-time system statistics. `vmstat` reports CPU/memory and I/O statistics, `top` provides process-level monitoring, and `iostat` focuses on disk I/O.",
      "examTip": "Use `vmstat 1 5` to capture CPU and memory statistics every second for five iterations."
    }
  ]
});
