db.tests.insertOne({
  "category": "linuxplus",
  "testId": 2,
  "testName": "Linux+ Practice Test #2 (Very Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which command will display detailed memory usage statistics, including total, used, and available memory, in a human-readable format?",
      "options": [
        "free -h",
        "vmstat -m",
        "top",
        "cat /proc/meminfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `free -h` command provides a concise summary of system memory usage in a human-readable format (MB, GB). `vmstat -m` shows slab memory info, `top` shows live resource usage, and `/proc/meminfo` contains raw details but isn't formatted for readability.",
      "examTip": "Use `free -h` for quick memory checks; `/proc/meminfo` for detailed analysis."
    },
    {
      "id": 2,
      "question": "A Linux administrator is troubleshooting a system where a user cannot write to their home directory. The administrator runs `ls -ld /home/user` and sees the following output:\n\n`drwxr-xr-x 3 user user 4096 Feb 20 12:00 /home/user`\n\nWhat is the MOST likely reason the user cannot write to their home directory?",
      "options": [
        "The directory is owned by root.",
        "The user's group lacks write permissions.",
        "The execute permission is missing on `/home/user`.",
        "The user's home directory is mounted read-only."
      ],
      "correctAnswerIndex": 3,
      "explanation": "If a directory is mounted read-only (e.g., due to `/etc/fstab` settings or a filesystem issue), no user—including the owner—can write to it. The output shows correct ownership (`user:user`) and permissions (`drwxr-xr-x`), so the issue is likely a read-only mount.",
      "examTip": "Check `mount | grep /home` to verify if a filesystem is mounted read-only."
    },
    {
      "id": 3,
      "question": "A user executes the following command but receives a 'Permission denied' error:\n\n`$ ./script.sh`\n\nWhich command should they run to resolve this?",
      "options": [
        "chmod +x script.sh",
        "sudo ./script.sh",
        "chown $USER script.sh",
        "ls -l script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "A script must have execute permissions to be run directly. `chmod +x script.sh` grants execute permissions, allowing it to be run as `./script.sh`. The other options do not address the permission issue directly.",
      "examTip": "If a script won't execute, check permissions with `ls -l` before modifying them."
    },
    {
      "id": 4,
      "question": "A system administrator needs to find all files in `/var/log` that were modified within the last 7 days. Which command should they use?",
      "options": [
        "find /var/log -mtime -7",
        "ls -lt --time=modify /var/log",
        "grep -r --mtime -7 /var/log",
        "stat -c '%y' /var/log/* | grep '7 days ago'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `find` command with `-mtime -7` searches for files modified within the last 7 days. `ls -lt` sorts files by modification time but does not filter by days. `grep` and `stat` are not designed for this purpose.",
      "examTip": "Use `find /path -mtime -N` to search for files modified within the last `N` days."
    },
    {
      "id": 5,
      "question": "**(PBQ)** You need to troubleshoot an issue where a server is not resolving domain names. Match each troubleshooting command with its function:",
      "options": [
        "1. `dig example.com`  ->  A. Queries DNS records from authoritative name servers",
        "2. `nslookup example.com`  ->  B. Resolves domain names using configured resolvers",
        "3. `cat /etc/resolv.conf`  ->  C. Displays current DNS configuration",
        "4. `systemctl restart systemd-resolved`  ->  D. Restarts the system's DNS resolver"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`dig` queries DNS servers, `nslookup` resolves hostnames, `/etc/resolv.conf` contains resolver settings, and restarting `systemd-resolved` refreshes system DNS services.",
      "examTip": "For deeper DNS troubleshooting, compare `dig +trace` with `nslookup` results."
    },
    {
      "id": 6,
      "question": "A Linux administrator needs to determine which process is listening on TCP port 443. Which command should they use?",
      "options": [
        "ss -tulnp | grep 443",
        "netstat -tulpn | grep 443",
        "lsof -i :443",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can identify which process is listening on port 443. `ss` and `netstat` provide similar output, and `lsof -i :443` lists open sockets.",
      "examTip": "Use `ss -tulnp` for modern systems; `netstat` is deprecated but still common."
    },
    {
      "id": 7,
      "question": "Which of the following files is responsible for mapping hostnames to IP addresses locally before querying external DNS?",
      "options": [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/hostname"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/hosts` allows manual mapping of hostnames to IP addresses, overriding DNS lookups.",
      "examTip": "If a domain resolves incorrectly, check `/etc/hosts` before assuming a DNS issue."
    },
    {
      "id": 8,
      "question": "Which command displays the current SELinux mode on a Linux system?",
      "options": [
        "getenforce",
        "sestatus",
        "semanage status",
        "systemctl status selinux"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`getenforce` returns the SELinux status as `Enforcing`, `Permissive`, or `Disabled`. `sestatus` provides more details but isn't a direct status command.",
      "examTip": "For full SELinux info, use `sestatus`; for a quick check, use `getenforce`."
    },
    {
      "id": 9,
      "question": "Which command lists all active cron jobs for the current user?",
      "options": [
        "crontab -l",
        "cron -l",
        "systemctl list-timers",
        "cat /etc/cron.d/user"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`crontab -l` displays the active cron jobs for the current user.",
      "examTip": "Use `crontab -e` to edit jobs; `crontab -l` to list them."
    },
    {
      "id": 10,
      "question": "Which command will force an immediate sync of all buffered disk writes to persistent storage?",
      "options": [
        "sync",
        "flush",
        "fsck",
        "commit"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `sync` command flushes all buffered filesystem writes to disk, ensuring data integrity. `flush` and `commit` are not standalone commands for this purpose, and `fsck` is used for filesystem checking, not syncing.",
      "examTip": "Run `sync` before unexpected shutdowns to reduce the risk of data loss."
    },
    {
      "id": 11,
      "question": "A user reports that their SSH session to a remote Linux server disconnects after a few minutes of inactivity. Which configuration parameter should be adjusted to prevent this?",
      "options": [
        "ClientAliveInterval",
        "KeepAlive",
        "TCPKeepAlive",
        "IdleTimeout"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ClientAliveInterval` in `sshd_config` controls how often the server sends keepalive messages to prevent idle disconnections. `KeepAlive` is not a valid SSH configuration option, and `TCPKeepAlive` only affects TCP-level keepalives, not session timeouts.",
      "examTip": "Set `ClientAliveInterval 300` to send a keepalive every 5 minutes and avoid idle disconnects."
    },
    {
      "id": 12,
      "question": "**(PBQ)** You need to verify network connectivity and diagnose an issue where a Linux server cannot reach an external website. Match each command to its function:",
      "options": [
        "1. `ping example.com`  ->  A. Tests basic connectivity and response time",
        "2. `traceroute example.com`  ->  B. Identifies network hops between the local system and the destination",
        "3. `dig example.com`  ->  C. Resolves domain names to IP addresses",
        "4. `netstat -rn`  ->  D. Displays the system’s current routing table"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ping` tests connectivity, `traceroute` traces network hops, `dig` queries DNS records, and `netstat -rn` shows routing information.",
      "examTip": "If a host is unreachable, check DNS resolution first, then routing, and finally network hops."
    },
    {
      "id": 13,
      "question": "A system administrator needs to display disk usage of all directories in `/var/log` in a human-readable format. Which command should be used?",
      "options": [
        "du -h /var/log",
        "df -h /var/log",
        "ls -lh /var/log",
        "lsblk --size /var/log"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `du -h` command shows directory sizes in a human-readable format. `df -h` reports filesystem space usage, `ls -lh` displays file sizes but not total directory usage, and `lsblk` is for block devices, not directory size.",
      "examTip": "Use `du -sh /path` for a summary of a directory’s size."
    },
    {
      "id": 14,
      "question": "Which command would you use to reload a systemd service’s configuration without restarting the service?",
      "options": [
        "systemctl reload <service>",
        "systemctl restart <service>",
        "systemctl stop <service> && systemctl start <service>",
        "systemctl daemon-reexec"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl reload` reloads a service’s configuration without restarting it, whereas `restart` fully stops and starts it. `daemon-reexec` is for reloading systemd itself, not services.",
      "examTip": "Use `reload` when applying minor configuration changes that don’t require a full restart."
    },
    {
      "id": 15,
      "question": "A Linux administrator needs to check which users are currently logged into the system. Which command should they run?",
      "options": [
        "w",
        "whoami",
        "id",
        "uptime"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `w` command shows all logged-in users along with their session details. `whoami` only shows the current user, `id` displays user/group IDs, and `uptime` reports system runtime but not logged-in users.",
      "examTip": "Use `w` for active user sessions and `who` for a simple logged-in user list."
    },
    {
      "id": 16,
      "question": "A user complains they cannot change their password due to a 'Password expired' message. What is the appropriate command for an administrator to reset their password expiration?",
      "options": [
        "chage -M 90 username",
        "passwd -e username",
        "usermod -p username",
        "groupmod -p username"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chage -M 90 username` sets the password maximum age to 90 days, preventing immediate expiration. `passwd -e` forces a password reset but does not adjust expiration settings.",
      "examTip": "Use `chage -l username` to check expiration settings before making changes."
    },
    {
      "id": 17,
      "question": "Which command provides a hierarchical tree view of active processes on a Linux system?",
      "options": [
        "pstree",
        "ps aux",
        "top",
        "htop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`pstree` displays processes in a hierarchical tree structure, making parent-child relationships clear. `ps aux` lists processes in a flat format, and `top/htop` provide interactive views but not tree structures.",
      "examTip": "Use `pstree -p` to include process IDs in the output."
    },
    {
      "id": 18,
      "question": "A user accidentally deleted their `.bashrc` file. Which command will restore it to its default state?",
      "options": [
        "cp /etc/skel/.bashrc ~/",
        "touch ~/.bashrc",
        "echo > ~/.bashrc",
        "source ~/.bashrc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The default user environment files are stored in `/etc/skel/`. Copying `.bashrc` from there restores it. `touch` and `echo` create empty files, and `source` reloads the file but won’t restore missing content.",
      "examTip": "For system-wide settings, check `/etc/profile` or `/etc/bash.bashrc`."
    },
    {
      "id": 19,
      "question": "A system administrator wants to check the disk partitioning scheme (MBR or GPT) on a Linux system. Which command should they use?",
      "options": [
        "parted -l",
        "lsblk",
        "blkid",
        "fdisk -t"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `parted -l` command displays partitioning information, including whether a disk is using MBR or GPT. `lsblk` and `blkid` list block devices but do not reveal partition schemes.",
      "examTip": "Use `gdisk -l /dev/sdX` for a detailed GPT/MBR breakdown."
    },
    {
      "id": 20,
      "question": "Which command allows a user to switch to another user account while preserving the current environment variables?",
      "options": [
        "su -",
        "sudo -i",
        "su",
        "sudo -u"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The `su` command switches users while preserving the current environment. `su -` starts a login shell, resetting the environment. `sudo -i` opens a root interactive shell, and `sudo -u` runs a command as another user but does not switch sessions.",
      "examTip": "Use `su` to switch users while keeping the same environment; use `su -` for a clean session."
    },
    {
      "id": 21,
      "question": "A system administrator needs to change the hostname of a Linux server without rebooting. Which command should they use?",
      "options": [
        "hostnamectl set-hostname newhostname",
        "echo 'newhostname' > /etc/hostname",
        "sysctl -w kernel.hostname=newhostname",
        "nmcli general hostname newhostname"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `hostnamectl set-hostname` command is the correct way to change the hostname persistently without rebooting. Editing `/etc/hostname` manually requires a restart, and `sysctl` does not handle hostnames.",
      "examTip": "Always verify the hostname change using `hostnamectl status`."
    },
    {
      "id": 22,
      "question": "A Linux administrator needs to display a list of all mounted filesystems along with their disk usage. Which command should they run?",
      "options": [
        "df -h",
        "du -h",
        "lsblk -f",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`df -h` provides filesystem usage in a human-readable format. `du -h` shows directory usage, `lsblk -f` lists block devices and filesystems, and `mount -l` lists mounted filesystems but not usage.",
      "examTip": "Use `df -h` for mounted filesystem usage; use `du -sh /path` for directory size analysis."
    },
    {
      "id": 23,
      "question": "Which file should be modified to set a system-wide default umask for all new user accounts?",
      "options": [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/default/umask",
        "/etc/shadow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/profile` sets environment variables, including `umask`, for all users. `/etc/bashrc` is executed per session, not globally. `/etc/shadow` stores user password hashes, and `/etc/default/umask` does not exist.",
      "examTip": "For user-specific settings, modify `~/.bashrc` instead of `/etc/profile`."
    },
    {
      "id": 24,
      "question": "**(PBQ)** You are troubleshooting why a Linux system cannot resolve domain names. Match each file or command with its function:",
      "options": [
        "1. `/etc/resolv.conf` -> A. Specifies DNS servers for the system",
        "2. `/etc/nsswitch.conf` -> B. Defines the order of name resolution sources",
        "3. `systemctl restart systemd-resolved` -> C. Restarts the system's DNS resolver",
        "4. `dig example.com` -> D. Queries a domain's DNS records"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/resolv.conf` lists DNS servers, `/etc/nsswitch.conf` defines lookup order, restarting `systemd-resolved` refreshes DNS settings, and `dig` queries DNS records.",
      "examTip": "If DNS fails, verify `/etc/resolv.conf` and check the resolver service status."
    },
    {
      "id": 25,
      "question": "A Linux system’s hard drive is almost full, and the administrator needs to find the largest files in `/var/log/`. Which command should be used?",
      "options": [
        "find /var/log -type f -size +100M",
        "du -sh /var/log/* | sort -rh | head -n 10",
        "ls -lhS /var/log",
        "df -h /var/log"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`du -sh /var/log/* | sort -rh | head -n 10` lists the largest files and directories sorted by size. `find` identifies large files but does not rank them. `ls -lhS` sorts files but does not account for directories.",
      "examTip": "Use `du -sh` for directory sizes; `find` for filtering large files."
    },
    {
      "id": 26,
      "question": "Which command allows a system administrator to set a user's password expiration policy, ensuring it must be changed every 60 days?",
      "options": [
        "chage -M 60 username",
        "passwd -x 60 username",
        "usermod -e 60 username",
        "shadowmod -m 60 username"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `chage -M` command sets the maximum password age. `passwd -x` is incorrect syntax, `usermod -e` modifies account expiration, and `shadowmod` is not a valid command.",
      "examTip": "Use `chage -l username` to check current password policies."
    },
    {
      "id": 27,
      "question": "A Linux administrator needs to configure a firewall rule using firewalld to allow incoming HTTP traffic. Which command should be used?",
      "options": [
        "firewall-cmd --permanent --add-service=http",
        "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
        "ufw allow 80",
        "nft add rule inet filter input tcp dport 80 accept"
      ],
      "correctAnswerIndex": 0,
      "explanation": "For firewalld, `firewall-cmd --permanent --add-service=http` is the correct command. `iptables`, `ufw`, and `nft` are used for other firewall types.",
      "examTip": "Always reload firewalld after adding a rule using `firewall-cmd --reload`."
    },
    {
      "id": 28,
      "question": "Which command will display kernel messages related to hardware events, system errors, and driver issues?",
      "options": [
        "dmesg",
        "journalctl -k",
        "cat /var/log/syslog",
        "systemctl status kernel"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`dmesg` displays kernel messages, including hardware events. `journalctl -k` filters system logs for kernel messages but is not available on all systems. `/var/log/syslog` contains general logs, not just kernel messages.",
      "examTip": "Use `dmesg | grep error` to quickly find system errors."
    },
    {
      "id": 29,
      "question": "Which command would a system administrator use to kill a process with PID 1234 gracefully?",
      "options": [
        "kill -15 1234",
        "kill -9 1234",
        "pkill 1234",
        "killall -SIGKILL 1234"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`kill -15` sends a SIGTERM signal, allowing the process to terminate cleanly. `kill -9` (SIGKILL) forcefully stops it without cleanup.",
      "examTip": "Always try `kill -15` first; use `kill -9` only if the process does not exit."
    },
    {
      "id": 30,
      "question": "Which of the following commands correctly extracts the contents of an archive named `backup.tar.gz` into the current directory?",
      "options": [
        "tar -xzvf backup.tar.gz",
        "tar -czvf backup.tar.gz",
        "gzip -d backup.tar.gz",
        "gunzip backup.tar.gz"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tar -xzvf` extracts a `.tar.gz` archive. The `-x` flag extracts, `-z` enables gzip decompression, `-v` provides verbose output, and `-f` specifies the file. `-c` is used for creating archives, while `gzip -d` and `gunzip` only decompress but do not extract.",
      "examTip": "Remember `tar -x` for extraction and `tar -c` for creating archives."
    },
    {
      "id": 31,
      "question": "Which command displays the last 100 lines of `/var/log/syslog` and continuously updates as new lines are added?",
      "options": [
        "tail -n 100 -f /var/log/syslog",
        "cat /var/log/syslog",
        "less /var/log/syslog",
        "head -100 /var/log/syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tail -n 100 -f` displays the last 100 lines of a file and continuously updates the output as new entries are written. `cat` prints the entire file at once, `less` allows scrolling but does not update in real-time, and `head` only shows the first lines.",
      "examTip": "Use `tail -f` when monitoring logs in real-time for troubleshooting."
    },
    {
      "id": 32,
      "question": "**(PBQ)** You need to manage a process running on a Linux system. Match each command with its purpose:",
      "options": [
        "1. `ps aux`  ->  A. Lists all running processes with details",
        "2. `kill -9 <PID>`  ->  B. Immediately terminates a process",
        "3. `nice -n 10 <command>`  ->  C. Starts a process with lower priority",
        "4. `pkill -u user`  ->  D. Kills all processes belonging to a specific user"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ps aux` lists processes, `kill -9` forcefully stops a process, `nice` starts a process with a lower priority, and `pkill -u` terminates all processes owned by a user.",
      "examTip": "Use `ps aux | grep <process>` to find process IDs before terminating them."
    },
    {
      "id": 33,
      "question": "Which command displays a list of all open network connections, including TCP and UDP sockets?",
      "options": [
        "ss -tunap",
        "netstat -an",
        "lsof -i",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can display open network connections. `ss -tunap` is the modern replacement for `netstat -an`, and `lsof -i` shows open network-related files.",
      "examTip": "Use `ss` instead of `netstat` for faster network connection analysis."
    },
    {
      "id": 34,
      "question": "A user needs to securely transfer a file from their local machine to a remote server over SSH. Which command should they use?",
      "options": [
        "scp file.txt user@remote:/home/user/",
        "rsync file.txt user@remote:/home/user/",
        "sftp file.txt user@remote:/home/user/",
        "ftp file.txt user@remote:/home/user/"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`scp` securely copies files over SSH. `rsync` can also use SSH but requires additional flags for secure transfer. `sftp` is an interactive file transfer session, and `ftp` is an insecure protocol.",
      "examTip": "Use `rsync -avz -e ssh` for efficient, encrypted file transfers with resume capability."
    },
    {
      "id": 35,
      "question": "Which of the following commands will display all active systemd timers?",
      "options": [
        "systemctl list-timers",
        "systemctl list-units --type=timer",
        "systemctl show-timers",
        "crontab -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-timers` lists all active timers in systemd. `list-units --type=timer` filters systemd units but does not show scheduled times. `crontab -l` lists cron jobs, not systemd timers.",
      "examTip": "Systemd timers replace cron jobs for modern task scheduling. Use `systemctl list-timers --all` to view inactive timers."
    },
    {
      "id": 36,
      "question": "Which of the following best describes the function of the `/proc` directory in Linux?",
      "options": [
        "Provides a virtual filesystem for kernel and process information",
        "Stores user configuration files",
        "Contains persistent logs and system messages",
        "Holds temporary files for system processes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/proc` directory is a virtual filesystem containing kernel and process-related information. It does not store user configurations, logs, or temporary files.",
      "examTip": "Use `cat /proc/cpuinfo` to view CPU details and `cat /proc/meminfo` for memory stats."
    },
    {
      "id": 37,
      "question": "A user needs to display all mounted filesystems along with their usage statistics in a human-readable format. Which command should they use?",
      "options": [
        "df -h",
        "du -sh /",
        "lsblk",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`df -h` shows all mounted filesystems and their usage in a human-readable format. `du -sh /` calculates space used by the root directory, `lsblk` shows block devices, and `mount -l` lists mounted filesystems but does not show usage.",
      "examTip": "Use `df -Th` to display filesystem types along with usage statistics."
    },
    {
      "id": 38,
      "question": "A user has an unresponsive process and needs to terminate it gracefully before resorting to a forceful kill. Which signal should they send first?",
      "options": [
        "SIGTERM",
        "SIGKILL",
        "SIGHUP",
        "SIGSTOP"
      ],
      "correctAnswerIndex": 0,
      "explanation": "SIGTERM (`kill -15 <PID>`) is the standard way to gracefully terminate a process. If the process does not respond, SIGKILL (`kill -9 <PID>`) can be used as a last resort. SIGHUP is used to reload configurations, and SIGSTOP pauses the process.",
      "examTip": "Always try `kill -15` before using `kill -9` to allow proper cleanup."
    },
    {
      "id": 39,
      "question": "Which command is used to configure and view system-wide date and time settings on a Linux system?",
      "options": [
        "timedatectl",
        "date",
        "hwclock",
        "ntpq"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`timedatectl` is the modern command for viewing and configuring system time, timezone, and synchronization settings. `date` displays the current date and time but does not configure settings, `hwclock` manages the hardware clock, and `ntpq` is used for NTP queries.",
      "examTip": "Use `timedatectl set-timezone <zone>` to change timezones easily."
    },
    {
      "id": 40,
      "question": "A Linux administrator needs to display all available storage devices and their associated partitions. Which command should they use?",
      "options": [
        "lsblk",
        "blkid",
        "fdisk -l",
        "mount"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsblk` provides a structured view of all block devices, including partitions and mount points. `blkid` displays device UUIDs and labels, `fdisk -l` lists partitions but lacks a tree structure, and `mount` only shows mounted filesystems.",
      "examTip": "Use `lsblk -f` to include filesystem details along with partitions."
    },
    {
      "id": 41,
      "question": "Which of the following commands will reload the Udev rules without rebooting the system?",
      "options": [
        "udevadm control --reload-rules",
        "systemctl restart udev",
        "modprobe -r udev && modprobe udev",
        "service udev reload"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`udevadm control --reload-rules` applies changes to Udev rules without requiring a restart. Restarting Udev via `systemctl` is not always necessary, and `modprobe` works with kernel modules, not Udev.",
      "examTip": "After reloading Udev rules, run `udevadm trigger` to apply them immediately."
    },
    {
      "id": 42,
      "question": "**(PBQ)** You need to troubleshoot a Linux system that is running out of disk space. Match each command with the type of storage information it provides:",
      "options": [
        "1. `df -h`  ->  A. Displays filesystem disk usage",
        "2. `du -sh /var/log`  ->  B. Shows disk usage for a specific directory",
        "3. `lsblk`  ->  C. Lists block devices and partitions",
        "4. `blkid`  ->  D. Displays UUID and filesystem type of storage devices"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`df -h` shows overall filesystem usage, `du -sh` provides directory-level usage, `lsblk` lists block devices, and `blkid` displays UUIDs and filesystem types.",
      "examTip": "Use `du` for per-directory storage checks and `df` for overall disk usage."
    },
    {
      "id": 43,
      "question": "Which option is required when using `useradd` to create a user and simultaneously generate a home directory?",
      "options": [
        "-m",
        "-d",
        "-s",
        "-U"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `-m` option with `useradd` ensures a home directory is created for the new user. `-d` specifies a custom home directory but does not create it by default, `-s` sets the default shell, and `-U` creates a user-specific group.",
      "examTip": "Use `useradd -m -d /custom/home user` to create a home directory in a specific location."
    },
    {
      "id": 44,
      "question": "A user attempts to execute a script but receives a 'Permission denied' error. The administrator verifies that the script has execute permissions. What is the most likely cause?",
      "options": [
        "The script uses an incorrect shebang line.",
        "The script is owned by another user.",
        "The script is missing read permissions.",
        "The user is not in the sudoers file."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If a script has execute permissions but still fails to run, it likely has an incorrect or missing shebang (`#!/bin/bash`), preventing the correct interpreter from executing it. Ownership and read permissions do not affect execution in this case.",
      "examTip": "Use `head -1 script.sh` to verify the shebang line if execution fails."
    },
    {
      "id": 45,
      "question": "Which command will allow a user to switch to the root user while preserving their current environment variables?",
      "options": [
        "sudo -s",
        "su -",
        "sudo -i",
        "su"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sudo -s` starts a root shell while preserving the current user's environment. `su -` starts a fresh root session with root's environment, while `sudo -i` simulates a full root login session.",
      "examTip": "Use `sudo -s` for temporary root access without altering the environment."
    },
    {
      "id": 46,
      "question": "A user needs to check the current default gateway configured on their Linux system. Which command should they use?",
      "options": [
        "ip route show",
        "netstat -r",
        "route -n",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can display the system's default gateway. `ip route show` is the modern replacement for `netstat -r` and `route -n`.",
      "examTip": "Use `ip route show default` to filter only the default gateway."
    },
    {
      "id": 47,
      "question": "A system administrator needs to determine which process is consuming the most CPU in real-time. Which command should they use?",
      "options": [
        "top",
        "ps aux --sort=-%cpu",
        "htop",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All the listed commands can identify high-CPU usage processes. `top` and `htop` provide real-time views, while `ps aux --sort=-%cpu` sorts processes by CPU consumption.",
      "examTip": "Use `htop` for an interactive and user-friendly process monitoring interface."
    },
    {
      "id": 48,
      "question": "Which command is used to assign a persistent static IP address on a system using NetworkManager?",
      "options": [
        "nmcli con mod <connection> ipv4.address <IP>",
        "ifconfig <interface> <IP> netmask <mask>",
        "ip addr add <IP>/<mask> dev <interface>",
        "netplan apply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nmcli con mod` updates the NetworkManager configuration for a connection, ensuring the IP persists after reboot. `ifconfig` and `ip addr add` set temporary addresses, and `netplan apply` is used in Ubuntu-based systems.",
      "examTip": "Use `nmcli con show` to list existing connections before modifying them."
    },
    {
      "id": 49,
      "question": "Which of the following commands will display the SELinux enforcement mode?",
      "options": [
        "getenforce",
        "sestatus",
        "ls -Z",
        "setenforce"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`getenforce` directly displays the current SELinux enforcement mode (`Enforcing`, `Permissive`, or `Disabled`). `sestatus` provides a more detailed status, while `ls -Z` and `setenforce` modify or inspect labels and policies.",
      "examTip": "Use `sestatus` for a full SELinux report, including policy and mode."
    },
    {
      "id": 50,
      "question": "Which command displays the UUID and filesystem type of a specified storage device?",
      "options": [
        "blkid",
        "lsblk",
        "df -T",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`blkid` retrieves UUIDs and filesystem types for storage devices. `lsblk` lists block devices but does not always show UUIDs, `df -T` reports filesystem types without UUIDs, and `mount -l` lists mounted filesystems but lacks UUID information.",
      "examTip": "Use `blkid` when configuring `/etc/fstab` with UUIDs for persistent mounts."
    },
    {
      "id": 51,
      "question": "A user wants to run a command that requires root privileges without switching to the root account. Which command should they use?",
      "options": [
        "sudo <command>",
        "su -c '<command>'",
        "pkexec <command>",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands allow executing commands with elevated privileges. `sudo` is the most common, `su -c` runs a command as root, and `pkexec` provides an alternative in some distributions.",
      "examTip": "Use `sudo -i` for a full root session if multiple privileged commands are needed."
    },
    {
      "id": 52,
      "question": "**(PBQ)** A system administrator needs to identify the cause of a high CPU load on a Linux server. Match each command with its purpose:",
      "options": [
        "1. `top`  ->  A. Displays real-time CPU usage",
        "2. `ps aux --sort=-%cpu`  ->  B. Lists processes sorted by CPU usage",
        "3. `vmstat`  ->  C. Provides system performance statistics",
        "4. `uptime`  ->  D. Displays system load averages"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`top` shows live CPU usage, `ps aux --sort=-%cpu` sorts processes by CPU consumption, `vmstat` provides performance metrics, and `uptime` displays load averages.",
      "examTip": "Use `uptime` first to check load, then `top` or `ps` to identify problematic processes."
    },
    {
      "id": 53,
      "question": "Which command is used to change the priority of a running process?",
      "options": [
        "renice",
        "nice",
        "chrt",
        "ps -o pri"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`renice` modifies the priority of an already running process. `nice` sets priority when starting a process, `chrt` sets real-time scheduling policies, and `ps -o pri` displays priority but does not change it.",
      "examTip": "Use `renice -n <value> -p <PID>` to adjust priority of an active process."
    },
    {
      "id": 54,
      "question": "Which command will list all available users on a Linux system?",
      "options": [
        "cut -d: -f1 /etc/passwd",
        "getent passwd",
        "awk -F: '{print $1}' /etc/passwd",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands retrieve the list of system users by extracting usernames from `/etc/passwd`. `getent passwd` queries the system database, while `cut` and `awk` filter the file manually.",
      "examTip": "Use `getent passwd | grep username` to verify if a user exists."
    },
    {
      "id": 55,
      "question": "Which of the following commands displays all currently mounted filesystems?",
      "options": [
        "mount",
        "df -h",
        "lsblk -f",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All options provide filesystem mount information. `mount` lists mounted filesystems, `df -h` shows usage statistics, and `lsblk -f` displays filesystem types and mount points.",
      "examTip": "Use `df -hT` to include filesystem types in the output."
    },
    {
      "id": 56,
      "question": "A system administrator wants to schedule a weekly job that runs every Sunday at 3:00 AM. Which cron syntax is correct?",
      "options": [
        "0 3 * * 0 /path/to/script.sh",
        "0 3 0 * * /path/to/script.sh",
        "3 0 * * 7 /path/to/script.sh",
        "0 3 7 * * /path/to/script.sh"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct cron syntax for running a job at 3:00 AM every Sunday is `0 3 * * 0`. The second field (0) represents Sunday in crontab.",
      "examTip": "Remember: minute hour day month weekday. Sunday = 0 or 7."
    },
    {
      "id": 57,
      "question": "Which command lists open files associated with a specific process ID (PID)?",
      "options": [
        "lsof -p <PID>",
        "ps -ef | grep <PID>",
        "netstat -nap | grep <PID>",
        "fdisk -l <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof -p <PID>` lists all open files associated with a specific process. `ps` shows process details but not open files, `netstat` displays network connections, and `fdisk` is unrelated to processes.",
      "examTip": "Use `lsof -i` for open network sockets and `lsof /path/to/file` to check file usage."
    },
    {
      "id": 58,
      "question": "A user needs to set up a persistent alias for `ls -la` to `ll`. Which file should they modify?",
      "options": [
        "~/.bashrc",
        "~/.bash_profile",
        "/etc/profile",
        "/etc/bash.bashrc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "User-specific aliases should be added to `~/.bashrc`, which is executed for interactive shell sessions. `~/.bash_profile` affects login shells, and `/etc/profile` and `/etc/bash.bashrc` affect all users globally.",
      "examTip": "After modifying `~/.bashrc`, run `source ~/.bashrc` to apply changes immediately."
    },
    {
      "id": 59,
      "question": "A system administrator suspects a process is creating excessive disk writes. Which command would best identify the responsible process?",
      "options": [
        "iotop",
        "iostat",
        "vmstat",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iotop` displays real-time disk I/O usage by process. `iostat` provides overall disk activity statistics, `vmstat` shows system performance, and `top` focuses on CPU/memory usage.",
      "examTip": "Use `iotop -o` to filter output for processes currently writing to disk."
    },
    {
      "id": 60,
      "question": "Which file should be modified to configure persistent static hostname settings on a Linux system using systemd?",
      "options": [
        "/etc/hostname",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/sysconfig/network"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/hostname` stores the system's persistent hostname, which is read at boot. `/etc/hosts` is for local name resolution, `/etc/resolv.conf` manages DNS settings, and `/etc/sysconfig/network` is used on older distributions.",
      "examTip": "Use `hostnamectl set-hostname <new_hostname>` to change the hostname on systemd-based systems."
    },
    {
      "id": 61,
      "question": "A system administrator needs to determine which process is using a specific network port. Which command should they use?",
      "options": [
        "ss -tulnp",
        "netstat -anp",
        "lsof -i :<port>",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All options can identify which process is using a specific network port. `ss -tulnp` is the modern replacement for `netstat -anp`, and `lsof -i :<port>` directly lists processes using the specified port.",
      "examTip": "Use `ss` for modern Linux systems, as `netstat` is deprecated."
    },
    {
      "id": 62,
      "question": "**(PBQ)** A system administrator is troubleshooting a slow network connection. Match each command with its function:",
      "options": [
        "1. `ping`  ->  A. Tests basic network connectivity",
        "2. `traceroute`  ->  B. Identifies network hops between the source and destination",
        "3. `netstat -s`  ->  C. Displays network statistics and errors",
        "4. `mtr`  ->  D. Combines ping and traceroute for continuous monitoring"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ping` tests connectivity, `traceroute` tracks network hops, `netstat -s` shows network statistics, and `mtr` provides real-time network path analysis.",
      "examTip": "Use `mtr` for diagnosing intermittent network issues as it continuously tracks latency."
    },
    {
      "id": 63,
      "question": "Which command is used to display the amount of free and used memory in a human-readable format?",
      "options": [
        "free -h",
        "vmstat -s",
        "top",
        "cat /proc/meminfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`free -h` displays memory usage in a human-readable format. `vmstat -s` shows memory statistics, `top` provides a real-time view, and `/proc/meminfo` contains raw memory details.",
      "examTip": "Use `free -h` for quick memory usage checks; `/proc/meminfo` for detailed data."
    },
    {
      "id": 64,
      "question": "A system administrator wants to list all user accounts on a Linux system. Which file should they inspect?",
      "options": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/login.defs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `/etc/passwd` file contains user account details, including usernames, UIDs, and home directories. `/etc/shadow` stores passwords, `/etc/group` lists group memberships, and `/etc/login.defs` defines user account policies.",
      "examTip": "Use `cut -d: -f1 /etc/passwd` to extract only usernames from the file."
    },
    {
      "id": 65,
      "question": "Which command will forcefully unmount a busy filesystem located at `/mnt/data`?",
      "options": [
        "umount -l /mnt/data",
        "unmount /mnt/data",
        "fuser -k /mnt/data",
        "rm -rf /mnt/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`umount -l` (lazy unmount) detaches a busy filesystem, allowing processes to close their references before final unmounting. `unmount` is not a valid command, `fuser -k` kills processes but does not unmount, and `rm -rf` deletes files but does not unmount.",
      "examTip": "Use `lsof +D /mnt/data` to check which processes are using the mount before unmounting."
    },
    {
      "id": 66,
      "question": "Which command is used to manually configure a new partition table on a storage device?",
      "options": [
        "fdisk",
        "parted",
        "mkfs",
        "lsblk"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`parted` is a modern tool for creating and modifying partition tables. `fdisk` works for MBR partitions but is less flexible for GPT disks, `mkfs` formats partitions, and `lsblk` only lists block devices.",
      "examTip": "Use `parted /dev/sdX` and `mklabel gpt` to create a GPT partition table."
    },
    {
      "id": 67,
      "question": "Which command should be used to set the default boot target on a systemd-based Linux distribution?",
      "options": [
        "systemctl set-default <target>",
        "systemctl isolate <target>",
        "init <target>",
        "runlevel <target>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl set-default` sets the default boot target for systemd systems. `systemctl isolate` switches targets but does not persist after reboot. `init` and `runlevel` are used in older SysVinit-based systems.",
      "examTip": "Use `systemctl get-default` to check the current default target."
    },
    {
      "id": 68,
      "question": "Which command will display detailed CPU information, including model, cores, and architecture?",
      "options": [
        "lscpu",
        "cat /proc/cpuinfo",
        "dmidecode -t processor",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide CPU details. `lscpu` summarizes architecture information, `/proc/cpuinfo` provides detailed per-core data, and `dmidecode -t processor` retrieves CPU details from the BIOS.",
      "examTip": "Use `lscpu` for a quick summary and `/proc/cpuinfo` for detailed per-core specs."
    },
    {
      "id": 69,
      "question": "A user wants to display a real-time view of system processes, including CPU and memory usage. Which command should they use?",
      "options": [
        "top",
        "ps aux",
        "vmstat",
        "uptime"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`top` provides an interactive, real-time display of system processes. `ps aux` lists processes but does not update dynamically, `vmstat` shows system performance stats, and `uptime` reports system load averages.",
      "examTip": "Use `htop` for an enhanced, user-friendly version of `top` with interactive features."
    },
    {
      "id": 70,
      "question": "Which command will modify the default permissions for newly created files in a user's session?",
      "options": [
        "umask",
        "chmod",
        "chown",
        "setfacl"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`umask` sets default permissions for new files and directories in a session. `chmod` modifies existing file permissions, `chown` changes ownership, and `setfacl` manages access control lists (ACLs).",
      "examTip": "Use `umask 022` for default 755 directories and 644 files."
    },
    {
      "id": 71,
      "question": "Which of the following commands will list the UUIDs of all available block devices?",
      "options": [
        "blkid",
        "lsblk -o UUID",
        "fdisk -l",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`blkid` retrieves the UUIDs and filesystem types of block devices. `lsblk -o UUID` can display UUIDs but may not always show them for all devices, `fdisk -l` lists partitions but not UUIDs, and `mount -l` only shows mounted filesystems.",
      "examTip": "Use `blkid | grep UUID` to filter results specifically for UUIDs."
    },
    {
      "id": 72,
      "question": "**(PBQ)** You need to identify potential performance bottlenecks on a Linux system. Match each command with its function:",
      "options": [
        "1. `iotop`  ->  A. Displays real-time disk I/O usage",
        "2. `htop`  ->  B. Interactive process monitoring",
        "3. `vmstat`  ->  C. Reports system-wide performance metrics",
        "4. `free -m`  ->  D. Displays memory usage in megabytes"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iotop` shows disk I/O per process, `htop` provides an interactive view of system processes, `vmstat` reports system-wide performance statistics, and `free -m` displays memory usage in megabytes.",
      "examTip": "Use `iotop` for disk bottlenecks, `htop` for CPU/memory usage, and `vmstat` for system-wide performance trends."
    },
    {
      "id": 73,
      "question": "A Linux system's `/home` partition is running out of space. The administrator suspects a specific user's files are consuming excessive storage. Which command would best identify the largest directories?",
      "options": [
        "du -sh /home/*",
        "df -h /home",
        "ls -lhR /home",
        "stat /home"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh /home/*` provides a summary of storage usage for each user in `/home`. `df -h` shows overall filesystem usage but not per-user data, `ls -lhR` lists files recursively but does not summarize directory sizes, and `stat` displays file metadata.",
      "examTip": "Use `du -sh /path/* | sort -hr` to list largest directories in descending order."
    },
    {
      "id": 74,
      "question": "Which command will display all available environment variables for the current session?",
      "options": [
        "printenv",
        "env",
        "set",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can display environment variables. `printenv` shows only exported variables, `env` lists environment variables for new processes, and `set` includes both shell and environment variables.",
      "examTip": "Use `export VAR=value` to set environment variables for child processes."
    },
    {
      "id": 75,
      "question": "Which command is used to display open network sockets and active listening ports on a Linux system?",
      "options": [
        "ss -tuln",
        "netstat -an",
        "lsof -i",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can show open sockets and listening ports. `ss -tuln` is the modern replacement for `netstat -an`, while `lsof -i` shows network connections related to processes.",
      "examTip": "Use `ss -tulnp` to include process names associated with network sockets."
    },
    {
      "id": 76,
      "question": "Which command will recursively change ownership of all files and directories under `/var/www` to the `webadmin` user and group?",
      "options": [
        "chown -R webadmin:webadmin /var/www",
        "chmod -R 755 /var/www",
        "usermod -R webadmin /var/www",
        "groupadd webadmin /var/www"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chown -R webadmin:webadmin /var/www` changes ownership recursively for all files and directories. `chmod` modifies permissions, `usermod` does not affect file ownership, and `groupadd` is used for creating groups.",
      "examTip": "Use `ls -l` to verify ownership changes after executing `chown`."
    },
    {
      "id": 77,
      "question": "A system administrator needs to create a new Logical Volume (LV) named `data` with a size of 10GB in the volume group `vg01`. Which command should they use?",
      "options": [
        "lvcreate -L 10G -n data vg01",
        "vgcreate vg01 data 10G",
        "pvcreate /dev/sdb1",
        "mkfs.ext4 /dev/vg01/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lvcreate -L 10G -n data vg01` creates a new logical volume named `data` with a size of 10GB in `vg01`. `vgcreate` creates a volume group, `pvcreate` initializes a physical volume, and `mkfs.ext4` formats an existing volume.",
      "examTip": "Remember LVM structure: Physical Volume → Volume Group → Logical Volume."
    },
    {
      "id": 78,
      "question": "Which command will display all currently loaded kernel modules on a Linux system?",
      "options": [
        "lsmod",
        "modinfo",
        "modprobe -l",
        "insmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsmod` lists all currently loaded kernel modules. `modinfo` provides details about a specific module, `modprobe -l` lists available modules but does not show loaded ones, and `insmod` manually loads modules.",
      "examTip": "Use `lsmod | grep <module>` to check if a specific module is loaded."
    },
    {
      "id": 79,
      "question": "A system administrator wants to check the hardware details of a Linux system, including motherboard and BIOS information. Which command should they use?",
      "options": [
        "dmidecode",
        "lscpu",
        "lsblk",
        "cat /proc/meminfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`dmidecode` retrieves detailed hardware information, including BIOS, CPU, and memory details. `lscpu` focuses only on CPU architecture, `lsblk` lists block devices, and `/proc/meminfo` provides memory statistics but no hardware details.",
      "examTip": "Run `sudo dmidecode -t system` for detailed system hardware information."
    },
    {
      "id": 80,
      "question": "A system administrator needs to check which groups a user belongs to. Which command should they run?",
      "options": [
        "groups <username>",
        "id -G <username>",
        "getent group | grep <username>",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide group membership information. `groups <username>` lists the groups a user belongs to, `id -G` shows group IDs, and `getent group | grep <username>` queries the system group database.",
      "examTip": "Use `id <username>` to see both user ID (UID) and group ID (GID) together."
    },
    {
      "id": 81,
      "question": "Which of the following commands will change the default shell for an existing user?",
      "options": [
        "chsh -s /bin/bash <username>",
        "usermod -s /bin/bash <username>",
        "echo '/bin/bash' > /etc/shells",
        "passwd -s /bin/bash <username>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chsh -s /bin/bash <username>` changes a user's default shell. `usermod -s` is also valid, but `echo` does not modify user settings, and `passwd -s` does not change shells.",
      "examTip": "Use `cat /etc/shells` to verify available shells before making changes."
    },
    {
      "id": 82,
      "question": "**(PBQ)** A system administrator needs to analyze system logs. Match each log file with its purpose:",
      "options": [
        "1. `/var/log/syslog`  ->  A. General system messages",
        "2. `/var/log/auth.log`  ->  B. User authentication and sudo attempts",
        "3. `/var/log/dmesg`  ->  C. Kernel boot messages",
        "4. `/var/log/cron`  ->  D. Scheduled job execution logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/var/log/syslog` contains general system messages, `/var/log/auth.log` records authentication attempts, `/var/log/dmesg` logs kernel boot messages, and `/var/log/cron` stores cron job execution details.",
      "examTip": "Use `journalctl -xe` on systemd-based distributions to view system logs interactively."
    },
    {
      "id": 83,
      "question": "A Linux administrator needs to configure persistent kernel parameters. Which file should they modify?",
      "options": [
        "/etc/sysctl.conf",
        "/proc/sys/kernel",
        "/etc/default/grub",
        "/boot/grub/grub.cfg"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/sysctl.conf` is used for persistent kernel parameter configurations. `/proc/sys/kernel` allows runtime changes, `/etc/default/grub` configures GRUB settings, and `/boot/grub/grub.cfg` is auto-generated.",
      "examTip": "Run `sysctl -p` after modifying `/etc/sysctl.conf` to apply changes without rebooting."
    },
    {
      "id": 84,
      "question": "Which of the following commands displays the number of lines, words, and characters in a file named `report.txt`?",
      "options": [
        "wc report.txt",
        "cat report.txt | wc",
        "grep -c '' report.txt",
        "awk '{print NR}' report.txt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`wc` (word count) displays the number of lines, words, and characters in a file. `cat | wc` works but is unnecessary, `grep -c ''` counts lines only, and `awk '{print NR}'` prints the line count.",
      "examTip": "Use `wc -l`, `wc -w`, or `wc -c` to count lines, words, or characters separately."
    },
    {
      "id": 85,
      "question": "A system administrator needs to configure a network interface with a static IP address on a modern Linux distribution using NetworkManager. Which command should they use?",
      "options": [
        "nmcli con mod <connection> ipv4.address <IP>",
        "ifconfig <interface> <IP>",
        "ip addr add <IP>/<mask> dev <interface>",
        "netplan apply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nmcli con mod <connection> ipv4.address <IP>` configures a persistent static IP for a NetworkManager-managed interface. `ifconfig` and `ip addr add` set temporary addresses, and `netplan apply` is used in Ubuntu systems.",
      "examTip": "Use `nmcli con show` to list available connections before modifying them."
    },
    {
      "id": 86,
      "question": "Which command will remove a software package along with its configuration files on a Debian-based system?",
      "options": [
        "apt-get purge <package>",
        "apt-get remove <package>",
        "dpkg -r <package>",
        "dpkg --purge <package>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`apt-get purge` removes the package and its configuration files. `apt-get remove` leaves configuration files, and `dpkg -r` also retains configuration files unless `--purge` is specified.",
      "examTip": "Use `dpkg --list | grep <package>` to verify installed packages before removing them."
    },
    {
      "id": 87,
      "question": "A system administrator needs to configure a scheduled job that runs every 15 minutes. Which cron entry is correct?",
      "options": [
        "*/15 * * * * /path/to/script.sh",
        "0,15,30,45 * * * * /path/to/script.sh",
        "*/15 0-23 * * * /path/to/script.sh",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed cron expressions correctly schedule a job to run every 15 minutes. `*/15` specifies every 15 minutes, and listing `0,15,30,45` achieves the same result.",
      "examTip": "Use `crontab -e` to edit cron jobs and `crontab -l` to list existing jobs."
    },
    {
      "id": 88,
      "question": "A user reports slow SSH login times. Which configuration file should be checked first?",
      "options": [
        "/etc/ssh/sshd_config",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/ssh/ssh_config"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/ssh/sshd_config` controls SSH server settings and may have `UseDNS yes`, which causes slow lookups. `/etc/hosts` and `/etc/resolv.conf` affect name resolution, but the SSH server configuration is the primary factor.",
      "examTip": "Set `UseDNS no` in `sshd_config` to speed up SSH logins on slow networks."
    },
    {
      "id": 89,
      "question": "Which command will list all systemd services, including those that are disabled or inactive?",
      "options": [
        "systemctl list-units --type=service --all",
        "systemctl list-services",
        "systemctl list-active",
        "systemctl list-running"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=service --all` lists all services, including inactive ones. `systemctl list-active` and `systemctl list-running` show only active or running services.",
      "examTip": "Use `systemctl is-enabled <service>` to check if a service is set to start on boot."
    },
    {
      "id": 90,
      "question": "Which command will display a real-time view of disk I/O usage by processes?",
      "options": [
        "iotop",
        "iostat",
        "vmstat",
        "df -h"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iotop` displays real-time disk I/O usage by process. `iostat` provides overall disk activity statistics, `vmstat` shows system performance, and `df -h` reports filesystem usage.",
      "examTip": "Use `iotop -o` to show only processes actively using disk I/O."
    },
    {
      "id": 91,
      "question": "A system administrator needs to disable a systemd service and ensure it does not start on boot. Which command should they use?",
      "options": [
        "systemctl disable --now <service>",
        "systemctl stop <service>",
        "systemctl mask <service>",
        "systemctl unmask <service>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl disable --now <service>` stops the service immediately and prevents it from starting at boot. `stop` only halts the service but does not disable it, and `mask` prevents manual starts but does not stop an active service.",
      "examTip": "Use `systemctl is-enabled <service>` to verify if a service is disabled."
    },
    {
      "id": 92,
      "question": "**(PBQ)** A system administrator is troubleshooting network connectivity. Match each command with its function:",
      "options": [
        "1. `ip addr show`  ->  A. Displays current IP address configuration",
        "2. `ip route show`  ->  B. Shows system routing table",
        "3. `dig example.com`  ->  C. Performs a DNS lookup",
        "4. `arp -a`  ->  D. Displays ARP cache entries"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip addr show` displays current network interfaces and IPs, `ip route show` lists routing tables, `dig` queries DNS records, and `arp -a` shows ARP cache entries.",
      "examTip": "Use `ip addr` for interface details and `ip route` to diagnose routing issues."
    },
    {
      "id": 93,
      "question": "Which of the following commands lists open files that are currently being accessed by a specific process?",
      "options": [
        "lsof -p <PID>",
        "ps aux | grep <PID>",
        "netstat -nap | grep <PID>",
        "fdisk -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof -p <PID>` lists all files opened by a process. `ps aux` shows process details but not open files, `netstat` displays network sockets, and `fdisk -l` is used for disk partitioning.",
      "examTip": "Use `lsof -i` for network connections and `lsof /path/to/file` to find which process is using a file."
    },
    {
      "id": 94,
      "question": "A user needs to check if their system’s clock is synchronized with an NTP server. Which command should they use?",
      "options": [
        "timedatectl status",
        "date",
        "hwclock",
        "ntpq -p"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`timedatectl status` shows whether the system clock is synchronized. `date` only displays the current time, `hwclock` manages the hardware clock, and `ntpq -p` queries NTP peers but does not confirm sync status.",
      "examTip": "Run `timedatectl set-ntp true` to enable automatic time synchronization."
    },
    {
      "id": 95,
      "question": "Which command would you use to reload a modified `sshd_config` file without restarting the SSH service?",
      "options": [
        "systemctl reload sshd",
        "systemctl restart sshd",
        "service sshd stop && service sshd start",
        "kill -HUP $(pidof sshd)"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl reload sshd` applies changes to `sshd_config` without restarting the service. `restart` would interrupt active sessions, `service stop/start` causes downtime, and `kill -HUP` is a lower-level alternative.",
      "examTip": "Use `sshd -t` to validate `sshd_config` changes before reloading."
    },
    {
      "id": 96,
      "question": "Which command will display the kernel version currently running on a Linux system?",
      "options": [
        "uname -r",
        "cat /proc/version",
        "lsb_release -a",
        "dmesg | grep Linux"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`uname -r` prints the currently running kernel version. `/proc/version` provides similar info but includes compilation details, `lsb_release -a` shows distribution information, and `dmesg` can contain kernel logs but is not reliable for version checks.",
      "examTip": "Use `uname -a` for additional system information like architecture and hostname."
    },
    {
      "id": 97,
      "question": "Which command will show the default gateway for a Linux system?",
      "options": [
        "ip route show default",
        "netstat -r",
        "route -n",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can display the default gateway. `ip route show default` is the modern equivalent, while `netstat -r` and `route -n` provide similar functionality on older systems.",
      "examTip": "Use `ip route | grep default` for a quick way to check the default gateway."
    },
    {
      "id": 98,
      "question": "Which command is used to modify or add new kernel parameters at runtime?",
      "options": [
        "sysctl -w",
        "modprobe",
        "lsmod",
        "insmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sysctl -w` modifies kernel parameters without rebooting. `modprobe` loads kernel modules, `lsmod` lists loaded modules, and `insmod` inserts a module manually.",
      "examTip": "To make changes persistent, add them to `/etc/sysctl.conf` and run `sysctl -p`."
    },
    {
      "id": 99,
      "question": "Which command should be used to check the disk usage of a directory and its subdirectories?",
      "options": [
        "du -sh /directory",
        "df -h /directory",
        "ls -lh /directory",
        "stat /directory"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh /directory` shows the total size of a directory and its contents. `df -h` displays filesystem usage, `ls -lh` lists file sizes but does not summarize directories, and `stat` provides metadata but not total directory usage.",
      "examTip": "Use `du -sh * | sort -hr` to list largest directories in descending order."
    },
    {
      "id": 100,
      "question": "Which command can be used to view detailed information about the available memory, including free, used, and swap memory?",
      "options": [
        "free -h",
        "vmstat -s",
        "cat /proc/meminfo",
        "All of the above"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`cat /proc/meminfo` provides the most detailed memory statistics, including free, used, swap, buffers, and caches. `free -h` is useful for a summarized view, and `vmstat -s` shows memory metrics but is less detailed.",
      "examTip": "Use `free -m` for quick memory usage checks and `/proc/meminfo` for deeper analysis."
    }
  ]
});
