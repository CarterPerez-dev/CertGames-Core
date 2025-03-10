db.tests.insertOne({
  "category": "linuxplus",
  "testId": 5,
  "testName": "CompTIA Linux+ (XK0-005) Practice Test #5 (Intermediate)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A Linux administrator needs to check which process is actively writing to a specific log file `/var/log/app.log`. Which command should they use?",
      "options": [
        "lsof +D /var/log | grep app.log",
        "ps aux | grep app.log",
        "tail -f /var/log/app.log",
        "stat /var/log/app.log"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof +D /var/log | grep app.log` identifies which process has the file open for writing. `ps aux | grep app.log` searches processes but does not show open files, `tail -f` monitors the file but does not show the writing process, and `stat` provides file metadata but not process details.",
      "examTip": "Use `lsof -p <PID>` to list all files opened by a specific process."
    },
    {
      "id": 2,
      "question": "Which command will display the SELinux context of a specific file?",
      "options": [
        "ls -Z <filename>",
        "getenforce <filename>",
        "sestatus <filename>",
        "chcon --list <filename>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ls -Z <filename>` displays the SELinux security context of a file. `getenforce` checks the SELinux mode, `sestatus` provides SELinux status information, and `chcon --list` is not a valid command.",
      "examTip": "Use `restorecon -Rv <directory>` to reset SELinux contexts to default values."
    },
    {
      "id": 3,
      "question": "A system administrator notices that a web server running on port 8080 is not accessible remotely. What is the correct sequence of actions to diagnose and resolve the issue?",
      "options": [
        "1) ss -tunlp | grep 8080 2) firewall-cmd --list-ports 3) firewall-cmd --permanent --add-port=8080/tcp && firewall-cmd --reload",
        "1) iptables -L -n | grep 8080 2) systemctl restart httpd 3) traceroute <client_ip>",
        "1) netstat -tulpn | grep 8080 2) ufw allow 8080/tcp 3) restart networking",
        "1) ps aux | grep httpd 2) chmod 755 /var/www/html 3) reboot the server"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking if the server is listening on port 8080, (2) verifying the firewall rules, and (3) adding an allow rule if necessary. Other sequences include unnecessary or incorrect steps.",
      "examTip": "Use `firewall-cmd --list-all` to see all firewall rules at once."
    },
    {
      "id": 4,
      "question": "Which command will display all user accounts that have a UID of 1000 or greater?",
      "options": [
        "awk -F: '$3 >= 1000' /etc/passwd",
        "getent passwd | grep 1000",
        "cut -d: -f1,3 /etc/passwd | grep 1000",
        "id -u 1000"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The command `awk -F: '$3 >= 1000' /etc/passwd` filters out users with a UID of 1000 or greater. `getent passwd | grep 1000` may return false positives, `cut` does not filter properly, and `id -u` shows the UID of a single user.",
      "examTip": "On most Linux systems, normal users have UIDs of 1000 and above."
    },
    {
      "id": 5,
      "question": "A system administrator wants to check if a service is actively listening on a network port. Which command should they use?",
      "options": [
        "ss -tunlp",
        "netstat -tulpn",
        "lsof -i",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ss -tunlp` is the modern command to check listening ports. `netstat -tulpn` is an older alternative, and `lsof -i` lists open network connections but does not directly focus on listening ports.",
      "examTip": "Use `ss -tunap` to include process names associated with open ports."
    },
    {
      "id": 6,
      "question": "Which command will display kernel log messages related to recent hardware events?",
      "options": [
        "dmesg",
        "journalctl -k",
        "cat /var/log/kern.log",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`journalctl -k` retrieves kernel messages, making it the preferred method on systemd systems. `dmesg` provides kernel logs but may not include recent events, and `/var/log/kern.log` contains historical logs but is not always enabled.",
      "examTip": "Use `journalctl -k -n 50` to view the last 50 kernel messages."
    },
    {
      "id": 7,
      "question": "Which of the following commands will display the number of file descriptors currently in use?",
      "options": [
        "cat /proc/sys/fs/file-nr",
        "ulimit -n",
        "lsof | wc -l",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide information about file descriptors. `cat /proc/sys/fs/file-nr` shows the number of allocated file descriptors, `ulimit -n` displays the limit per user, and `lsof | wc -l` counts open files.",
      "examTip": "Use `sysctl fs.file-max` to check the system-wide file descriptor limit."
    },
    {
      "id": 8,
      "question": "Which command will immediately unmount a filesystem that is currently in use?",
      "options": [
        "umount -l /mnt/data",
        "fuser -km /mnt/data",
        "umount -f /mnt/data",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`fuser -km /mnt/data` forcefully kills processes using the mount before unmounting. `umount -l` (lazy unmount) detaches the filesystem but does not immediately remove it, and `umount -f` may not work on busy mounts.",
      "examTip": "Use `lsof +D /mnt/data` to check which processes are using the mount before unmounting."
    },
    {
      "id": 9,
      "question": "Which command will display the current runlevel in a SysVinit-based Linux system?",
      "options": [
        "runlevel",
        "systemctl get-default",
        "who -r",
        "init --show"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`runlevel` displays the previous and current runlevel on SysVinit systems. `systemctl get-default` applies to systemd, while `who -r` provides similar information but is less commonly used.",
      "examTip": "Use `systemctl list-units --type=target` to see all available runlevels (targets) in systemd."
    },
    {
      "id": 10,
      "question": "A Linux administrator notices that a critical application fails to start after a system reboot on a system running SELinux in enforcing mode. The application logs show 'Permission denied' errors for library files located in a custom directory. Which steps must the administrator perform to allow the application to run while maintaining SELinux in enforcing mode?",
      "options": [
        "1) Disable SELinux by editing /etc/selinux/config; 2) Reboot; 3) Ensure the application’s custom directory is in the default library path",
        "1) Set SELINUX=permissive in /etc/selinux/config; 2) Reboot; 3) Run chcon -t bin_t on the custom directory and files",
        "1) Identify the correct SELinux context with chcon or semanage; 2) Assign matching context (e.g., lib_t or usr_t) to the custom directory and files; 3) Restorefilecon to ensure context consistency",
        "1) Use setenforce 0 before running the application; 2) Return SELinux to enforcing mode after application start; 3) Repeat each reboot"
      ],
      "correctAnswerIndex": 2,
      "explanation": "When an application uses libraries in non-standard directories, SELinux can block access if the context is not set correctly. Using tools like chcon or semanage fcontext to match the appropriate context (e.g., lib_t) and then running restorecon ensures persistent, correct labeling. Disabling or setting SELinux to permissive mode is not necessary and reduces security. Temporarily disabling SELinux is an ineffective solution for production environments.",
      "examTip": "Always consider proper SELinux labeling over disabling enforcement. Use 'audit2allow' if you need to create custom policy modules for complex scenarios."
    },
    {
      "id": 11,
      "question": "Which command will display a list of recently executed commands, along with their timestamps?",
      "options": [
        "history",
        "cat ~/.bash_history",
        "journalctl _COMM=bash",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide access to command history. `history` shows recent commands, `cat ~/.bash_history` lists commands but may not include timestamps, and `journalctl _COMM=bash` logs shell activity in systemd-based distributions.",
      "examTip": "Use `HISTTIMEFORMAT=\"%F %T \" history` to show timestamps in `history` output."
    },
    {
      "id": 12,
      "question": "Which command will display the permissions of the `/etc/shadow` file?",
      "options": [
        "ls -l /etc/shadow",
        "stat /etc/shadow",
        "getfacl /etc/shadow",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands display file permissions. `ls -l` shows basic permissions, `stat` provides detailed metadata, and `getfacl` displays access control lists if ACLs are enabled.",
      "examTip": "Use `ls -ld /etc/shadow` to check directory permissions as well."
    },
    {
      "id": 13,
      "question": "A system administrator suspects high memory usage is causing system slowdowns. What is the correct sequence of actions?",
      "options": [
        "1) free -m 2) ps aux --sort=-%mem 3) kill -9 <PID>",
        "1) vmstat 1 5 2) swapoff -a 3) reboot",
        "1) top 2) renice -n 10 <PID> 3) pkill -9 <process>",
        "1) htop 2) fuser -k <process> 3) echo 3 > /proc/sys/vm/drop_caches"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) using `free -m` to check memory usage, (2) identifying high-memory processes with `ps aux --sort=-%mem`, and (3) terminating the problematic process if needed.",
      "examTip": "Use `kill -15` before `kill -9` to allow processes to exit gracefully."
    },
    {
      "id": 14,
      "question": "Which command will display all kernel modules currently loaded on a Linux system?",
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
      "id": 15,
      "question": "Which of the following commands will modify a user’s primary group?",
      "options": [
        "usermod -g <group> <user>",
        "groupmod -g <group> <user>",
        "gpasswd -a <user> <group>",
        "chgrp <group> <file>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`usermod -g <group> <user>` changes a user's primary group. `groupmod` modifies group IDs, `gpasswd -a` adds a user to a group but does not change the primary group, and `chgrp` modifies file ownership.",
      "examTip": "Use `id <user>` to verify a user’s group memberships after modification."
    },
    {
      "id": 16,
      "question": "Which command will display all processes currently being executed by a specific user?",
      "options": [
        "ps -u <username>",
        "pgrep -u <username>",
        "top -u <username>",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can list a specific user's processes. `ps -u` provides process details, `pgrep -u` returns process IDs, and `top -u` shows real-time usage.",
      "examTip": "Use `ps -eo user,pid,%cpu,%mem,command | grep <username>` for detailed filtering."
    },
    {
      "id": 17,
      "question": "Which of the following commands will display a list of currently mounted filesystems?",
      "options": [
        "mount",
        "df -h",
        "findmnt",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands display mounted filesystems. `mount` shows active mounts, `df -h` provides usage statistics, and `findmnt` presents a tree view of mount points.",
      "examTip": "Use `findmnt -t ext4` to filter by filesystem type."
    },
    {
      "id": 18,
      "question": "Which file is used to define a system-wide message displayed before login?",
      "options": [
        "/etc/issue",
        "/etc/motd",
        "/etc/hostname",
        "/etc/profile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/issue` contains the pre-login message displayed before the login prompt. `/etc/motd` is shown after login, `/etc/hostname` stores the system’s hostname, and `/etc/profile` sets system-wide environment variables.",
      "examTip": "Use `echo 'Authorized Users Only' > /etc/issue` to set a warning message."
    },
    {
      "id": 19,
      "question": "Which command will recursively change ownership of all files and directories under `/var/www` to `webadmin`?",
      "options": [
        "chown -R webadmin:webadmin /var/www",
        "chmod -R 755 /var/www",
        "usermod -R webadmin /var/www",
        "groupadd webadmin /var/www"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chown -R webadmin:webadmin /var/www` changes ownership recursively. `chmod` modifies permissions, `usermod` does not affect file ownership, and `groupadd` creates a new group but does not modify ownership.",
      "examTip": "Use `ls -l /var/www` to verify ownership changes."
    },
    {
      "id": 20,
      "question": "Which command will show all users currently logged into the system?",
      "options": [
        "who",
        "w",
        "users",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands display information about logged-in users. `who` lists sessions, `w` provides additional details, and `users` shows a simple list of usernames.",
      "examTip": "Use `last` to see a history of user logins."
    },
    {
      "id": 21,
      "question": "Which command allows an administrator to see the default gateway of a Linux system?",
      "options": [
        "ip route show default",
        "netstat -rn",
        "route -n",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip route show default` is the modern command for checking the system’s default gateway. `netstat -rn` and `route -n` provide similar information but are deprecated.",
      "examTip": "Use `ip route get <IP>` to check which gateway is used for a specific destination."
    },
    {
      "id": 22,
      "question": "Which command would you use to display a hierarchical view of running processes?",
      "options": [
        "pstree",
        "ps aux",
        "htop",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pstree` shows processes in a tree format, displaying parent-child relationships. `ps aux` lists all processes, `htop` provides real-time monitoring, and `top` focuses on CPU/memory usage.",
      "examTip": "Use `pstree -p` to include process IDs in the output."
    },
    {
      "id": 23,
      "question": "A system administrator needs to diagnose a network issue where a server cannot reach external sites. What is the correct sequence of actions?",
      "options": [
        "1) ping 8.8.8.8 2) ip route show 3) systemctl restart networking",
        "1) nslookup google.com 2) traceroute 8.8.8.8 3) systemctl restart NetworkManager",
        "1) ip a 2) netstat -rn 3) dig @8.8.8.8 google.com",
        "1) ifconfig 2) route -n 3) telnet google.com 80"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The best troubleshooting order is: (1) checking IP addresses (`ip a`), (2) checking the routing table (`netstat -rn`), and (3) verifying DNS resolution (`dig @8.8.8.8 google.com`). Other sequences include deprecated or unnecessary steps.",
      "examTip": "Use `ping <gateway>` first to determine if local networking is functional."
    },
    {
      "id": 24,
      "question": "Which command will reload all Udev rules without rebooting the system?",
      "options": [
        "udevadm control --reload-rules",
        "systemctl restart udev",
        "modprobe -r udev && modprobe udev",
        "service udev reload"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`udevadm control --reload-rules` reloads Udev rules without rebooting. Restarting `udev` may be necessary in some cases, `modprobe` is for kernel modules, and `service` is deprecated on systemd-based systems.",
      "examTip": "Run `udevadm trigger` after reloading rules to apply changes immediately."
    },
    {
      "id": 25,
      "question": "Which file should be modified to set system-wide environment variables in a persistent manner?",
      "options": [
        "/etc/environment",
        "/etc/profile",
        "~/.bashrc",
        "/etc/default/locale"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/environment` is the preferred location for setting system-wide environment variables. `/etc/profile` affects interactive login shells, `~/.bashrc` applies only to a specific user, and `/etc/default/locale` is used for language settings.",
      "examTip": "Use `source /etc/environment` to apply changes without rebooting."
    },
    {
      "id": 26,
      "question": "Which command will display the number of available and used file descriptors on a system?",
      "options": [
        "cat /proc/sys/fs/file-nr",
        "ulimit -n",
        "lsof | wc -l",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All commands provide file descriptor information. `cat /proc/sys/fs/file-nr` shows the system-wide limit, `ulimit -n` displays user limits, and `lsof | wc -l` counts open files.",
      "examTip": "Use `sysctl fs.file-max` to check the system’s maximum file descriptor limit."
    },
    {
      "id": 27,
      "question": "Which command will display the current password aging settings for a user?",
      "options": [
        "chage -l <username>",
        "passwd -S <username>",
        "getent shadow <username>",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chage -l <username>` provides a detailed password aging report. `passwd -S` shows a brief summary, and `getent shadow` displays expiration details but requires root access.",
      "examTip": "Use `chage -E <date> <username>` to set an account expiration date."
    },
    {
      "id": 28,
      "question": "Which command will list all currently loaded kernel modules?",
      "options": [
        "lsmod",
        "modinfo",
        "modprobe -l",
        "depmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsmod` lists loaded kernel modules. `modinfo` provides details about a specific module, `modprobe -l` lists available modules, and `depmod` updates module dependencies.",
      "examTip": "Use `lsmod | grep <module>` to check if a specific module is loaded."
    },
    {
      "id": 29,
      "question": "Which command will provide real-time monitoring of disk I/O activity?",
      "options": [
        "iotop",
        "iostat",
        "vmstat",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide disk I/O monitoring. `iotop` shows per-process I/O usage, `iostat` reports overall disk activity, and `vmstat` includes CPU, memory, and I/O statistics.",
      "examTip": "Use `iotop -o` to filter only processes currently performing disk I/O."
    },
    {
      "id": 30,
      "question": "Which command will safely unmount a busy filesystem?",
      "options": [
        "umount -l /mnt/data",
        "fuser -km /mnt/data",
        "umount -f /mnt/data",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`fuser -km /mnt/data` kills processes using the mount before unmounting. `umount -l` (lazy unmount) detaches the filesystem but does not immediately remove it, and `umount -f` may fail if processes are still accessing the filesystem.",
      "examTip": "Use `lsof +D /mnt/data` to check which processes are using the mount before unmounting."
    },
    {
      "id": 31,
      "question": "Which command will display the amount of swap space currently in use?",
      "options": [
        "free -h",
        "swapon --show",
        "cat /proc/swaps",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide information on swap space. `free -h` displays memory and swap usage, `swapon --show` lists active swap partitions, and `cat /proc/swaps` provides detailed swap device information.",
      "examTip": "Use `swapoff -a` followed by `swapon -a` to clear and reinitialize swap usage."
    },
    {
      "id": 32,
      "question": "Which command will modify the file permissions of `script.sh` so that only the owner can execute it?",
      "options": [
        "chmod 700 script.sh",
        "chmod 744 script.sh",
        "chmod 755 script.sh",
        "chmod 777 script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chmod 700 script.sh` grants read, write, and execute permissions only to the owner. `744` and `755` allow others to execute the script, while `777` grants full permissions to all users.",
      "examTip": "Use `ls -l script.sh` to verify file permissions after modification."
    },
    {
      "id": 33,
      "question": "A system administrator needs to recover a deleted log file that was still open by a running process. What is the correct sequence of actions?",
      "options": [
        "1) lsof | grep deleted 2) cp /proc/<PID>/fd/<FD> /var/log/recovered.log 3) restart process",
        "1) tail -f /var/log/syslog 2) kill -9 <PID> 3) recover /var/log/syslog",
        "1) stat /var/log/syslog 2) fuser -m /var/log/syslog 3) pkill -9 <process>",
        "1) echo 3 > /proc/sys/vm/drop_caches 2) mount -o remount /var 3) recover /var/log/syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct sequence is (1) identifying the deleted file using `lsof`, (2) recovering it from `/proc/<PID>/fd/`, and (3) restarting the associated process if necessary. Other sequences contain unnecessary or destructive steps.",
      "examTip": "Recover open but deleted files before terminating the associated process."
    },
    {
      "id": 34,
      "question": "Which command allows an administrator to analyze network traffic on a Linux system?",
      "options": [
        "tcpdump",
        "wireshark",
        "tshark",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed tools are used for network traffic analysis. `tcpdump` is CLI-based, `wireshark` provides a GUI, and `tshark` is a command-line alternative to Wireshark.",
      "examTip": "Use `tcpdump -i eth0 port 80` to capture HTTP traffic on `eth0`."
    },
    {
      "id": 35,
      "question": "Which command will display all active systemd services, including failed ones?",
      "options": [
        "systemctl list-units --type=service --all",
        "systemctl list-units --failed",
        "systemctl list-services",
        "service --status-all"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=service --all` lists all active and inactive services. `list-units --failed` only shows failed services, `list-services` is not a valid command, and `service --status-all` is for SysVinit.",
      "examTip": "Use `systemctl --failed` for a quick view of failed services."
    },
    {
      "id": 36,
      "question": "Which file contains the user account information, including UID, GID, home directory, and shell?",
      "options": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/login.defs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/passwd` contains user details such as username, UID, GID, home directory, and shell. `/etc/shadow` stores password hashes, `/etc/group` manages group memberships, and `/etc/login.defs` defines system-wide login policies.",
      "examTip": "Use `getent passwd <user>` to retrieve a user's entry from `/etc/passwd`."
    },
    {
      "id": 37,
      "question": "Which command will display detailed statistics about CPU, memory, and I/O usage over time?",
      "options": [
        "sar",
        "top",
        "uptime",
        "free -m"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sar` (part of the `sysstat` package) collects and reports system performance data over time. `top` provides real-time monitoring, `uptime` shows system load averages, and `free -m` reports current memory usage.",
      "examTip": "Use `sar -u 5 10` to collect CPU usage data every 5 seconds for 10 intervals."
    },
    {
      "id": 38,
      "question": "Which of the following commands will list all failed SSH login attempts?",
      "options": [
        "grep 'Failed password' /var/log/auth.log",
        "journalctl -u sshd | grep 'Failed password'",
        "cat /var/log/secure | grep 'Failed password'",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can display failed SSH login attempts. `grep` searches logs for authentication failures, `journalctl` retrieves SSH logs in systemd-based systems, and `/var/log/secure` is used in Red Hat-based systems.",
      "examTip": "Use `lastb` to see a history of failed login attempts."
    },
    {
      "id": 39,
      "question": "Which command will display the disk space usage of all mounted filesystems in human-readable format?",
      "options": [
        "df -h",
        "du -sh /*",
        "lsblk",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`df -h` shows available disk space on all mounted filesystems in a human-readable format. `du -sh /*` reports per-directory usage, `lsblk` lists block devices, and `mount -l` shows mounted filesystems without usage details.",
      "examTip": "Use `df -Th` to display filesystem types alongside disk usage."
    },
    {
      "id": 40,
      "question": "Which command will display all currently available systemd targets?",
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
      "id": 41,
      "question": "Which command will display a list of all open network sockets, including TCP and UDP connections?",
      "options": [
        "ss -tunap",
        "netstat -tulnp",
        "lsof -i",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide network socket details. `ss -tunap` is the modern command, `netstat -tulnp` is the older equivalent, and `lsof -i` lists open network-related files.",
      "examTip": "Use `ss -tuln` to quickly check listening ports."
    },
    {
      "id": 42,
      "question": "Which command will display the status of the firewall on a system using `firewalld`?",
      "options": [
        "firewall-cmd --state",
        "iptables -L",
        "ufw status",
        "systemctl status firewalld"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`firewall-cmd --state` checks if `firewalld` is running. `iptables -L` lists rules for iptables, `ufw status` is for UFW-based systems, and `systemctl status firewalld` provides a service-level status but not firewall rules.",
      "examTip": "Use `firewall-cmd --list-all` to view active firewall rules."
    },
    {
      "id": 43,
      "question": "A Linux administrator is troubleshooting high system load. What is the correct sequence of actions?",
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
      "id": 44,
      "question": "Which file contains user account expiration settings?",
      "options": [
        "/etc/shadow",
        "/etc/passwd",
        "/etc/security/limits.conf",
        "/etc/group"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/shadow` contains user password expiration and aging settings. `/etc/passwd` stores basic user information, `/etc/security/limits.conf` configures resource limits, and `/etc/group` manages group memberships.",
      "examTip": "Use `chage -l <username>` to view expiration details for a specific user."
    },
    {
      "id": 45,
      "question": "Which command is used to analyze and diagnose memory-related performance issues in real time?",
      "options": [
        "vmstat",
        "free -m",
        "top",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide memory-related information. `vmstat` reports memory, swap, and I/O statistics over time, `free -m` shows total, used, and available memory, and `top` provides real-time usage details.",
      "examTip": "Use `vmstat 1 5` to collect memory statistics every second for five iterations."
    },
    {
      "id": 46,
      "question": "Which command will display the system's uptime, logged-in users, and load averages?",
      "options": [
        "uptime",
        "w",
        "top",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide uptime and load information. `uptime` directly reports system uptime and load, `w` includes logged-in users and their activities, and `top` shows live system performance details.",
      "examTip": "Use `w` to see user activity along with system load averages."
    },
    {
      "id": 47,
      "question": "Which command is used to create a new Logical Volume (LV) named `data` with a size of 50GB inside the volume group `vg01`?",
      "options": [
        "lvcreate -L 50G -n data vg01",
        "vgcreate vg01 data 50G",
        "pvcreate /dev/sdb1",
        "mkfs.ext4 /dev/vg01/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lvcreate -L 50G -n data vg01` creates a new logical volume inside an existing volume group. `vgcreate` creates a volume group, `pvcreate` initializes a physical volume, and `mkfs.ext4` formats an existing logical volume.",
      "examTip": "Use `lvextend -L +10G /dev/vg01/data` to expand an existing logical volume."
    },
    {
      "id": 48,
      "question": "Which command is used to configure kernel parameters permanently?",
      "options": [
        "echo 'vm.swappiness=10' >> /etc/sysctl.conf",
        "sysctl -w vm.swappiness=10",
        "echo 10 > /proc/sys/vm/swappiness",
        "modprobe vm.swappiness=10"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Appending `vm.swappiness=10` to `/etc/sysctl.conf` ensures the change persists across reboots. `sysctl -w` modifies parameters at runtime, `/proc/sys/vm/swappiness` allows temporary changes, and `modprobe` is unrelated to sysctl settings.",
      "examTip": "Use `sysctl -p` after modifying `/etc/sysctl.conf` to apply changes immediately."
    },
    {
      "id": 49,
      "question": "Which of the following commands will show all systemd services that failed to start?",
      "options": [
        "systemctl --failed",
        "systemctl list-units --state=failed",
        "journalctl -p err",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can help identify failed services. `systemctl --failed` and `systemctl list-units --state=failed` list failed units, while `journalctl -p err` shows error logs related to service failures.",
      "examTip": "Use `journalctl -xe` for detailed logs of failed service starts."
    },
    {
      "id": 50,
      "question": "Which command allows an administrator to change the ownership of all files in `/var/www` to the user `webadmin` and group `developers`?",
      "options": [
        "chown -R webadmin:developers /var/www",
        "chmod -R 775 /var/www",
        "usermod -G developers webadmin",
        "groupmod -n developers webadmin"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chown -R webadmin:developers /var/www` recursively changes ownership. `chmod` modifies permissions, `usermod` modifies group memberships but not ownership, and `groupmod` changes group names.",
      "examTip": "Use `ls -ld /var/www` to verify ownership after changing it."
    },
    {
      "id": 51,
      "question": "A system administrator suspects that a recent kernel update has caused the system to fail during boot. The system reaches the GRUB menu but does not fully load. What should be the FIRST step to troubleshoot this issue?",
      "options": [
        "Select the previous kernel version from the GRUB menu and attempt to boot.",
        "Reinstall the GRUB bootloader using a live CD.",
        "Edit the `/etc/default/grub` file to disable graphical boot and regenerate GRUB configuration.",
        "Boot into single-user mode and uninstall the latest kernel package."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The safest first step is to select the previous working kernel from the GRUB menu. Reinstalling GRUB or modifying configuration files should be done only if reverting to an older kernel fails.",
      "examTip": "If a kernel update causes boot failure, always attempt to boot a previous working kernel before making permanent changes."
    },
    {
      "id": 52,
      "question": "A user reports that their system clock is incorrect even after manually setting it using the `date` command. The administrator finds that after a reboot, the clock resets to an incorrect value. What is the MOST likely cause of this issue?",
      "options": [
        "The hardware clock (RTC) is not synchronized with the system clock.",
        "The timezone is incorrectly set in `/etc/timezone`.",
        "The system is not using NTP to synchronize time.",
        "The user does not have the necessary permissions to change the time."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If the system clock resets after a reboot, the hardware clock (RTC) is likely not synchronized. Use `hwclock --systohc` to synchronize the system clock to the hardware clock.",
      "examTip": "Use `timedatectl` to check and configure both the system clock and hardware clock synchronization."
    },
    {
      "id": 53,
      "question": "A Linux administrator needs to diagnose slow disk performance on a production database server. What is the correct sequence of actions?",
      "options": [
        "1) iostat -x 1 10 2) df -h 3) fsck -y /dev/sdX",
        "1) vmstat 1 5 2) iotop 3) tune2fs -o journal_data_writeback /dev/sdX1",
        "1) iotop 2) smartctl -H /dev/sdX 3) fstrim -v /",
        "1) free -m 2) mount -o remount,noatime /dev/sdX1 3) dd if=/dev/zero of=/testfile bs=1M count=1024"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The best troubleshooting sequence is (1) using `iotop` to check per-process I/O usage, (2) running `smartctl` to check disk health, and (3) using `fstrim` to optimize SSD performance.",
      "examTip": "For SSDs, use `fstrim` periodically to improve performance and longevity."
    },
    {
      "id": 54,
      "question": "Which of the following commands will list all systemd services, including inactive and failed ones?",
      "options": [
        "systemctl list-units --type=service --all",
        "systemctl list-services",
        "systemctl list-running",
        "systemctl show-services"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=service --all` lists all services regardless of state. `systemctl list-services` is not a valid command, `systemctl list-running` shows only active services, and `systemctl show-services` does not exist.",
      "examTip": "Use `systemctl --failed` to display only failed services."
    },
    {
      "id": 55,
      "question": "A server running a critical application crashes unexpectedly. The administrator needs to identify which process triggered the crash. Which command should be used?",
      "options": [
        "journalctl -k -n 50",
        "dmesg -T | tail -50",
        "cat /var/log/syslog | grep 'kernel panic'",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can help diagnose kernel-related crashes. `journalctl -k -n 50` shows recent kernel logs, `dmesg -T` converts timestamps into human-readable format, and `grep 'kernel panic'` searches for crash-related logs.",
      "examTip": "If a kernel panic occurs, check `/var/crash/` for core dumps and analyze logs for failure patterns."
    },
    {
      "id": 56,
      "question": "A system administrator notices that a large number of failed SSH login attempts are originating from a specific IP address. What is the BEST action to take?",
      "options": [
        "Block the IP address using `firewalld` or `iptables`.",
        "Disable password authentication in SSH and use key-based authentication.",
        "Limit SSH access to known IP ranges using TCP wrappers.",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed actions help secure SSH access. Blocking the IP address prevents brute-force attempts, key-based authentication improves security, and restricting access limits exposure.",
      "examTip": "Use `fail2ban` to automatically ban IPs that trigger multiple failed SSH attempts."
    },
    {
      "id": 57,
      "question": "Which command will show detailed disk usage statistics per directory under `/home`?",
      "options": [
        "du -sh /home/*",
        "df -h /home",
        "ls -lh /home",
        "stat -c %s /home/*"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh /home/*` displays disk usage for each directory under `/home`. `df -h` shows overall filesystem usage, `ls -lh` lists file sizes but does not summarize directories, and `stat` provides metadata but not cumulative directory sizes.",
      "examTip": "Use `du -sh * | sort -hr` to list the largest directories first."
    },
    {
      "id": 58,
      "question": "Which command would an administrator use to identify which files were recently modified on a Linux system?",
      "options": [
        "find / -type f -mtime -1",
        "ls -ltR /",
        "stat /var/log/*",
        "journalctl --since '1 day ago'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find / -type f -mtime -1` locates all files modified in the last 24 hours. `ls -ltR` sorts files by modification time but does not filter by date, `stat` provides metadata for a single file, and `journalctl` logs system events but not file modifications.",
      "examTip": "Use `find /path -type f -mmin -60` to find files modified within the last hour."
    },
    {
      "id": 59,
      "question": "Which file contains the mapping of UIDs to usernames on a Linux system?",
      "options": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/login.defs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/passwd` stores user account information, including UIDs. `/etc/shadow` contains password hashes, `/etc/group` defines group memberships, and `/etc/login.defs` sets system-wide login policies.",
      "examTip": "Use `getent passwd` to retrieve user information from `/etc/passwd`."
    },
    {
      "id": 60,
      "question": "A systemd-based Linux server must automatically start a custom monitoring service that depends on network connectivity and a database service. The custom monitoring service is named 'monitor.service,' the network service is 'network-online.target,' and the database service is 'postgresql.service.' Which approach ensures the correct startup order and automatic restarts if the monitoring service fails?",
      "options": [
        "Create a cron job @reboot for monitor.service, referencing postgresql.service within the script. No changes to systemd files are required.",
        "Modify /etc/rc.local to include 'service monitor start' after checking netstat for open ports. Add 'Restart=always' to /etc/sysconfig/monitor.conf.",
        "Create /etc/systemd/system/monitor.service with 'After=network-online.target postgresql.service' and 'Wants=network-online.target postgresql.service'; include 'Restart=on-failure' and enable the service with systemctl.",
        "Write a custom shell script that pings the database host, then starts monitor.service; schedule it with cron every minute until it detects connectivity."
      ],
      "correctAnswerIndex": 2,
      "explanation": "Systemd requires defining dependencies (After=) and relationships (Wants=) to ensure services start in the correct order. Including 'Restart=on-failure' enables automatic restarts. Placing these directives in the [Unit] and [Service] sections of an explicit monitor.service file is the recommended method. Cron jobs and rc.local hacks offer less control and reliability.",
      "examTip": "Use systemd’s native dependency management and service restart policies for resilient service orchestration. Always enable 'network-online.target' for services that need fully established network connectivity."
    },
    {
      "id": 61,
      "question": "A system administrator needs to limit the number of simultaneous SSH connections from a single IP address to prevent brute-force attacks. Which configuration file should be modified?",
      "options": [
        "/etc/ssh/sshd_config",
        "/etc/security/limits.conf",
        "/etc/hosts.allow",
        "/etc/pam.d/sshd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/ssh/sshd_config` file contains the `MaxStartups` directive, which limits simultaneous SSH connections per IP. Other files control access policies, PAM authentication, and TCP wrappers but do not handle SSH connection limits.",
      "examTip": "Use `MaxStartups 3:50:10` in `sshd_config` to control SSH connection limits dynamically."
    },
    {
      "id": 62,
      "question": "Which command will display the real-time network bandwidth usage for each active connection?",
      "options": [
        "iftop",
        "nload",
        "bmon",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed tools provide real-time network bandwidth usage. `iftop` displays active network connections, `nload` provides per-interface bandwidth graphs, and `bmon` offers a detailed visual breakdown of network traffic.",
      "examTip": "Use `iftop -i eth0` to monitor traffic on a specific interface."
    },
    {
      "id": 63,
      "question": "A Linux administrator notices that a web server is running out of disk space. What is the correct sequence of actions to diagnose and resolve the issue?",
      "options": [
        "1) df -h 2) du -sh /var/log 3) truncate -s 0 /var/log/access.log",
        "1) ls -lh /var/www 2) rm -rf /var/www/html 3) reboot",
        "1) fsck -y /dev/sdX 2) mount -o remount / 3) clear_cache",
        "1) journalctl --vacuum-time=7d 2) shred -u /var/log/messages 3) fstrim -v /"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking filesystem usage (`df -h`), (2) identifying large directories (`du -sh`), and (3) truncating logs instead of deleting them to avoid application crashes.",
      "examTip": "Use `du -sh /var/* | sort -hr` to list the largest directories first."
    },
    {
      "id": 64,
      "question": "Which command is used to list all available systemd targets?",
      "options": [
        "systemctl list-units --type=target",
        "systemctl get-default",
        "runlevel",
        "who -r"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=target` lists all available systemd targets. `systemctl get-default` shows the default boot target, `runlevel` applies to SysVinit, and `who -r` provides similar information but is less commonly used.",
      "examTip": "Use `systemctl set-default <target>` to change the default boot target."
    },
    {
      "id": 65,
      "question": "Which of the following commands will display all currently scheduled systemd timers?",
      "options": [
        "systemctl list-timers --all",
        "crontab -l",
        "atq",
        "ls /etc/systemd/system/*.timer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-timers --all` lists all scheduled and inactive systemd timers. `crontab -l` lists cron jobs, `atq` shows scheduled `at` jobs, and `ls /etc/systemd/system/*.timer` lists timer files but does not show their schedule.",
      "examTip": "Use `systemctl cat <timer>.timer` to view a timer’s configuration."
    },
    {
      "id": 66,
      "question": "Which command will display failed login attempts for users on a Linux system?",
      "options": [
        "lastb",
        "journalctl -u sshd | grep 'Failed password'",
        "cat /var/log/auth.log | grep 'Failed password'",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can display failed login attempts. `lastb` shows failed logins from the `btmp` file, `journalctl` retrieves logs in systemd-based systems, and `/var/log/auth.log` stores authentication failures.",
      "examTip": "Use `lastb | head -10` to view the last 10 failed login attempts."
    },
    {
      "id": 67,
      "question": "A system administrator needs to manually extend an LVM logical volume. Which command should they use?",
      "options": [
        "lvextend -L +10G /dev/vg01/lv_data",
        "vgextend vg01 /dev/sdb1",
        "pvcreate /dev/sdb1",
        "resize2fs /dev/vg01/lv_data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lvextend -L +10G /dev/vg01/lv_data` extends an existing logical volume. `vgextend` adds a physical volume to a volume group, `pvcreate` initializes a new physical volume, and `resize2fs` resizes the filesystem after volume extension.",
      "examTip": "Use `lvextend --resizefs` to extend both the volume and filesystem in one step."
    },
    {
      "id": 68,
      "question": "Which command allows a user to execute commands as another user without switching sessions?",
      "options": [
        "sudo -u <user> <command>",
        "su <user> -c <command>",
        "pkexec <command>",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands allow executing commands as another user without switching sessions. `sudo -u` runs a command as another user, `su -c` executes commands as another user, and `pkexec` provides an alternative.",
      "examTip": "Use `sudo -u <user> -s` to open a shell as another user."
    },
    {
      "id": 69,
      "question": "Which command will identify which process is holding a file open and preventing its deletion?",
      "options": [
        "lsof | grep <filename>",
        "ps aux | grep <filename>",
        "netstat -nap | grep <filename>",
        "fuser -m <filename>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof | grep <filename>` lists the process keeping a file open. `ps aux` finds running processes but does not track open files, `netstat -nap` is for network connections, and `fuser -m` finds processes using a mount point but not specific files.",
      "examTip": "Use `lsof +D <directory>` to see all files open in a directory."
    },
    {
      "id": 70,
      "question": "Which command allows an administrator to change the ownership of all files in `/var/www` to the user `webadmin` and group `developers`?",
      "options": [
        "chown -R webadmin:developers /var/www",
        "chmod -R 775 /var/www",
        "usermod -G developers webadmin",
        "groupmod -n developers webadmin"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chown -R webadmin:developers /var/www` recursively changes ownership. `chmod` modifies permissions, `usermod` modifies group memberships but not ownership, and `groupmod` changes group names.",
      "examTip": "Use `ls -ld /var/www` to verify ownership after changing it."
    },
    {
      "id": 71,
      "question": "A system administrator needs to create a new partition on `/dev/sdb` and format it as XFS. Which sequence of commands should be used?",
      "options": [
        "1) parted /dev/sdb mkpart primary xfs 1MiB 10GiB 2) mkfs.xfs /dev/sdb1 3) mount /dev/sdb1 /mnt/data",
        "1) fdisk /dev/sdb 2) mkfs.ext4 /dev/sdb1 3) mount /dev/sdb1 /mnt/data",
        "1) gparted 2) mkfs -t xfs /dev/sdb1 3) mount -a",
        "1) lvcreate -L 10G -n lv_data vg01 2) mkfs.xfs /dev/vg01/lv_data 3) mount /dev/vg01/lv_data /mnt/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct method involves using `parted` to create the partition, `mkfs.xfs` to format it, and `mount` to attach it to a directory. Other sequences either use incorrect partitioning tools or assume an LVM setup when not specified.",
      "examTip": "Use `lsblk` after partitioning to confirm changes before formatting."
    },
    {
      "id": 72,
      "question": "Which of the following is the BEST way to apply security patches to a Red Hat-based Linux system while ensuring the system stays up-to-date?",
      "options": [
        "dnf update",
        "dnf upgrade --security",
        "yum update -y",
        "dnf install --force-security"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`dnf upgrade --security` applies only security updates without upgrading unnecessary packages. `dnf update` updates all packages, `yum update -y` is an older alternative, and `dnf install --force-security` is not a valid option.",
      "examTip": "Use `dnf check-update --security` to preview available security updates before applying them."
    },
    {
      "id": 73,
      "question": "A user is unable to change their password due to a 'Password expired' message. What command should the administrator use to allow them to set a new password?",
      "options": [
        "chage -d 0 <username>",
        "passwd -e <username>",
        "usermod -U <username>",
        "chage -M 90 <username>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chage -d 0 <username>` forces the user to change their password at the next login. `passwd -e` also forces a change but does not expire it immediately. `usermod -U` unlocks an account but does not address password expiration.",
      "examTip": "Use `chage -l <username>` to check password expiration settings before making changes."
    },
    {
      "id": 74,
      "question": "A Linux administrator wants to monitor failed SSH login attempts in real time. Which command should they use?",
      "options": [
        "journalctl -u sshd -f",
        "grep 'Failed password' /var/log/auth.log",
        "tail -f /var/log/secure | grep 'Failed password'",
        "journalctl --since '10 minutes ago' -u sshd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`journalctl -u sshd -f` provides real-time monitoring of SSH authentication logs. `grep` and `tail` allow filtering logs but do not provide continuous updates.",
      "examTip": "Use `fail2ban-client status sshd` if Fail2Ban is installed to see blocked IPs."
    },
    {
      "id": 75,
      "question": "A system administrator is troubleshooting slow system performance. What is the correct sequence of actions?",
      "options": [
        "1) uptime 2) vmstat 1 5 3) kill -9 <PID>",
        "1) iostat -x 1 5 2) free -m 3) renice -10 <PID>",
        "1) top 2) ps aux --sort=-%cpu 3) kill -15 <PID>",
        "1) sar -u 5 10 2) ionice -c 3 -p <PID> 3) sync"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The correct sequence is (1) using `top` to monitor CPU/memory usage, (2) sorting processes by CPU utilization with `ps aux`, and (3) terminating a problematic process using `kill -15` for a graceful shutdown.",
      "examTip": "Use `htop` for an interactive alternative to `top`."
    },
    {
      "id": 76,
      "question": "A system administrator needs to verify whether a specific kernel module is loaded. Which command should they use?",
      "options": [
        "lsmod | grep <module>",
        "modinfo <module>",
        "modprobe -r <module>",
        "depmod -a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsmod | grep <module>` checks if a kernel module is currently loaded. `modinfo` provides details about a module but does not indicate if it's loaded. `modprobe -r` removes a module, and `depmod -a` updates dependencies.",
      "examTip": "Use `modinfo <module>` before loading or removing a kernel module."
    },
    {
      "id": 77,
      "question": "A Linux system is experiencing high disk I/O wait times. Which command would BEST help identify the process causing the issue?",
      "options": [
        "iotop",
        "iostat -x 1 10",
        "vmstat 1 5",
        "top -o %IO"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iotop` shows real-time disk I/O usage by process, making it the best tool for diagnosing high disk wait times. `iostat -x` and `vmstat` provide system-wide I/O statistics but do not show per-process details.",
      "examTip": "Use `iotop -o` to filter only processes currently performing I/O operations."
    },
    {
      "id": 78,
      "question": "Which command is used to add an additional network route persistently on a Red Hat-based system?",
      "options": [
        "nmcli con mod <connection> +ipv4.routes '<destination> <gateway>'",
        "ip route add <destination> via <gateway>",
        "route add -net <destination> gw <gateway>",
        "echo '<destination> via <gateway>' >> /etc/sysconfig/network-scripts/route-eth0"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct persistent method is `nmcli con mod` for NetworkManager-managed interfaces. `ip route add` is temporary, `route add -net` is deprecated, and modifying `/etc/sysconfig/network-scripts/route-eth0` requires a restart.",
      "examTip": "Use `ip route show` to verify active routes before modifying them."
    },
    {
      "id": 79,
      "question": "A system administrator needs to update all installed packages on a Debian-based system while ensuring critical services remain running. Which command should they use?",
      "options": [
        "apt-get upgrade",
        "apt-get dist-upgrade",
        "apt-get update && apt-get upgrade",
        "dpkg --configure -a"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`apt-get update && apt-get upgrade` updates package lists and installs upgrades without removing packages. `dist-upgrade` may remove packages, and `dpkg --configure -a` is used to fix broken package installations.",
      "examTip": "Use `apt list --upgradable` before running updates to see pending upgrades."
    },
    {
      "id": 80,
      "question": "Which of the following commands will list all USB devices connected to a Linux system?",
      "options": [
        "lsusb",
        "usb-devices",
        "dmesg | grep usb",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsusb` provides a list of all connected USB devices. `usb-devices` displays detailed information about USB devices, and `dmesg | grep usb` shows kernel logs for USB events.",
      "examTip": "Use `lsusb -t` to display USB devices in a tree format."
    },
    {
      "id": 81,
      "question": "A Linux administrator needs to check which PCI devices are installed on the system. Which command should they use?",
      "options": [
        "lspci",
        "lsblk",
        "dmidecode -t pci",
        "lsusb"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lspci` lists all PCI devices on a system. `lsblk` shows block devices, `dmidecode -t pci` is not a valid option, and `lsusb` lists USB devices.",
      "examTip": "Use `lspci -v` for detailed information about each PCI device."
    },
    {
      "id": 82,
      "question": "Which command will configure an application to automatically start on boot in a systemd-based Linux distribution?",
      "options": [
        "systemctl enable <service>",
        "systemctl start <service>",
        "chkconfig <service> on",
        "update-rc.d <service> enable"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl enable <service>` ensures a service starts automatically at boot. `systemctl start` only starts it for the current session, `chkconfig` is for older SysVinit systems, and `update-rc.d` is for Debian-based systems that do not use systemd.",
      "examTip": "Use `systemctl is-enabled <service>` to verify if a service is set to start at boot."
    },
    {
      "id": 83,
      "question": "A system administrator needs to troubleshoot why a scheduled job did not execute. What is the correct sequence of actions?",
      "options": [
        "1) crontab -l 2) grep CRON /var/log/syslog 3) check user permissions",
        "1) systemctl list-timers 2) atq 3) restart crond",
        "1) ps aux | grep cron 2) systemctl restart cron 3) cat /etc/crontab",
        "1) crontab -e 2) chmod +x /etc/cron.daily/job 3) reboot"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) verifying the job with `crontab -l`, (2) checking logs for execution errors using `grep CRON /var/log/syslog`, and (3) ensuring the user has the necessary permissions to run the job.",
      "examTip": "Use `crontab -e` to edit the user’s cron jobs and ensure correct syntax."
    },
    {
      "id": 84,
      "question": "Which command will display the file type of a given file?",
      "options": [
        "file <filename>",
        "stat <filename>",
        "ls -l <filename>",
        "strings <filename>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`file <filename>` determines the type of a file. `stat` shows metadata, `ls -l` displays permissions and size, and `strings` extracts readable text from binary files.",
      "examTip": "Use `file -i <filename>` to display MIME type information."
    },
    {
      "id": 85,
      "question": "A system administrator needs to configure a server to allow only key-based SSH authentication. Which of the following settings should be modified in `/etc/ssh/sshd_config`?",
      "options": [
        "PasswordAuthentication no",
        "PermitRootLogin no",
        "ClientAliveInterval 300",
        "AllowUsers admin"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Setting `PasswordAuthentication no` forces SSH authentication to use keys instead of passwords. `PermitRootLogin no` disables root SSH access but does not enforce key-based authentication, `ClientAliveInterval` is for session timeouts, and `AllowUsers` restricts logins but does not enforce keys.",
      "examTip": "After making changes, restart SSH using `systemctl restart sshd`."
    },
    {
      "id": 86,
      "question": "Which command will display the UUID and filesystem type of a given block device?",
      "options": [
        "blkid",
        "lsblk -f",
        "df -T",
        "fdisk -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`blkid` retrieves UUIDs and filesystem types for block devices. `lsblk -f` also shows this information, but `df -T` lists filesystem types without UUIDs, and `fdisk -l` does not display UUIDs.",
      "examTip": "Use `blkid | grep UUID` to quickly locate UUIDs."
    },
    {
      "id": 87,
      "question": "Which command will modify the permissions of an existing directory so that only the owner can read, write, and execute files within it?",
      "options": [
        "chmod 700 /path/to/directory",
        "chmod 755 /path/to/directory",
        "chmod 644 /path/to/directory",
        "chmod 600 /path/to/directory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chmod 700` grants full permissions to the owner while denying access to others. `755` allows read/execute for others, `644` is for files (not directories), and `600` removes execute permissions.",
      "examTip": "Use `ls -ld /path/to/directory` to verify directory permissions."
    },
    {
      "id": 88,
      "question": "Which of the following commands will display the dependencies of a given installed package on a Debian-based system?",
      "options": [
        "apt-cache depends <package>",
        "dpkg -l <package>",
        "apt show <package>",
        "dpkg -s <package>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`apt-cache depends <package>` lists package dependencies. `dpkg -l` shows installed packages but not dependencies, `apt show` provides general package details, and `dpkg -s` gives package status but not dependency resolution.",
      "examTip": "Use `apt-cache rdepends <package>` to see reverse dependencies."
    },
    {
      "id": 89,
      "question": "Which command will display system-wide resource usage statistics over time?",
      "options": [
        "sar",
        "vmstat",
        "iostat",
        "mpstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sar` (from the `sysstat` package) collects and reports system performance data over time. `vmstat` provides real-time performance metrics, `iostat` focuses on disk I/O, and `mpstat` shows CPU usage per core.",
      "examTip": "Use `sar -u 5 10` to collect CPU usage data every 5 seconds for 10 iterations."
    },
    {
      "id": 90,
      "question": "A user is unable to access a mounted NFS share. The administrator suspects an issue with the NFS client configuration. Which file should they check first?",
      "options": [
        "/etc/fstab",
        "/etc/exports",
        "/etc/nfs.conf",
        "/var/log/nfslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/fstab` contains persistent mount configurations. If the NFS share is not mounting, incorrect options in `/etc/fstab` may be the cause. `/etc/exports` is for NFS servers, `/etc/nfs.conf` configures NFS behavior, and `/var/log/nfslog` logs NFS events.",
      "examTip": "Use `showmount -e <server>` to verify available NFS shares before troubleshooting the client."
    },
    {
      "id": 91,
      "question": "A Linux administrator needs to ensure that user `jdoe` is automatically logged out after 10 minutes of inactivity. Which file should they modify?",
      "options": [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/security/limits.conf",
        "/etc/systemd/logind.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Adding `TMOUT=600` to `/etc/profile` enforces automatic logout after 10 minutes. `/etc/bash.bashrc` affects interactive shells but does not enforce session timeouts, `/etc/security/limits.conf` handles resource limits, and `/etc/systemd/logind.conf` configures system-wide session handling.",
      "examTip": "Use `export TMOUT=600` in a user’s `.bashrc` file for a user-specific setting."
    },
    {
      "id": 92,
      "question": "A server running multiple containers has run out of disk space. The administrator suspects that old unused container images are taking up space. Which command should they use to remove all unused images?",
      "options": [
        "docker image prune -a",
        "docker rmi $(docker images -q)",
        "docker container prune",
        "docker system df"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`docker image prune -a` removes all unused images. `docker rmi $(docker images -q)` deletes all images, including active ones. `docker container prune` removes stopped containers, and `docker system df` displays disk usage.",
      "examTip": "Use `docker system prune -a` to remove unused images, containers, and volumes."
    },
    {
      "id": 93,
      "question": "A system administrator needs to analyze why a service fails to start on boot. What is the correct sequence of actions?",
      "options": [
        "1) systemctl status <service> 2) journalctl -u <service> 3) systemctl restart <service>",
        "1) ps aux | grep <service> 2) systemctl start <service> 3) reboot",
        "1) dmesg | grep <service> 2) systemctl enable <service> 3) systemctl restart <service>",
        "1) systemctl stop <service> 2) systemctl disable <service> 3) rm -rf /etc/systemd/system/<service>.service"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The best approach is (1) checking service status with `systemctl status`, (2) reviewing logs with `journalctl -u <service>`, and (3) restarting the service if no errors are found.",
      "examTip": "Use `systemctl enable <service>` to ensure it starts automatically on boot."
    },
    {
      "id": 94,
      "question": "Which command will create an archive of the `/home` directory using the xz compression algorithm?",
      "options": [
        "tar -cJvf home.tar.xz /home",
        "tar -czvf home.tar.gz /home",
        "zip -r home.zip /home",
        "gzip -c /home > home.tar.gz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tar -cJvf` creates an archive with xz compression. `tar -czvf` uses gzip instead of xz, `zip -r` creates a `.zip` archive, and `gzip` compresses files but does not preserve directory structures like tar.",
      "examTip": "Use `tar -cJf` instead of `-cJvf` if verbose output is not needed."
    },
    {
      "id": 95,
      "question": "Which command will display all persistent mount points configured on a Linux system?",
      "options": [
        "cat /etc/fstab",
        "mount",
        "findmnt",
        "df -h"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/fstab` contains persistent mount configurations. `mount` lists currently mounted filesystems, `findmnt` displays the mount hierarchy, and `df -h` shows disk space usage.",
      "examTip": "Use `findmnt --fstab` to display only persistent mounts from `/etc/fstab`."
    },
    {
      "id": 96,
      "question": "Which command is used to list all active network interfaces and their associated IP addresses?",
      "options": [
        "ip addr show",
        "ifconfig -a",
        "nmcli device show",
        "ss -tunlp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip addr show` lists all active network interfaces and IP addresses. `ifconfig -a` works on older systems, `nmcli device show` provides NetworkManager-managed interface details, and `ss -tunlp` shows network sockets but not interface IPs.",
      "examTip": "Use `ip -c a` for a colorized output of network interfaces."
    },
    {
      "id": 97,
      "question": "A Linux administrator needs to modify the default permissions for new files created by all users. Which file should be edited?",
      "options": [
        "/etc/login.defs",
        "/etc/security/limits.conf",
        "/etc/profile",
        "/etc/skel"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/login.defs` contains the default umask setting, which controls new file permissions. `/etc/security/limits.conf` manages resource limits, `/etc/profile` sets environment variables, and `/etc/skel` provides default files for new user home directories.",
      "examTip": "Set `UMASK 027` in `/etc/login.defs` for more restrictive default file permissions."
    },
    {
      "id": 98,
      "question": "Which command will display all running Docker containers on a system?",
      "options": [
        "docker ps",
        "docker container list",
        "docker images",
        "docker network ls"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`docker ps` lists all running containers. `docker container list` is incorrect syntax, `docker images` shows available images, and `docker network ls` displays available Docker networks.",
      "examTip": "Use `docker ps -a` to see both running and stopped containers."
    },
    {
      "id": 99,
      "question": "A system administrator needs to test an SSH connection to a remote server without logging in. Which command should they use?",
      "options": [
        "ssh -v user@remote-server exit",
        "ssh -q user@remote-server",
        "telnet remote-server 22",
        "nc -zv remote-server 22"
      ],
      "correctAnswerIndex": 3,
      "explanation": "`nc -zv remote-server 22` checks if the SSH port is open without logging in. `ssh -v` provides verbose output but still initiates a login attempt, `ssh -q` suppresses messages but connects, and `telnet` is deprecated for testing SSH.",
      "examTip": "Use `nc -zvw3 remote-server 22` for a faster timeout when testing SSH."
    },
    {
      "id": 100,
      "question": "Which command will display all kernel messages related to hardware errors?",
      "options": [
        "dmesg | grep -i 'error'",
        "journalctl -k -p err",
        "cat /var/log/kern.log | grep 'error'",
        "grep 'error' /proc/kmsg"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`journalctl -k -p err` retrieves kernel logs related to hardware errors. `dmesg | grep` searches for errors but does not filter by priority, `/var/log/kern.log` may not be available on all systems, and `/proc/kmsg` is a raw kernel log interface.",
      "examTip": "Use `journalctl -k -p warning` to include warning-level messages."
    }
  ]
});
