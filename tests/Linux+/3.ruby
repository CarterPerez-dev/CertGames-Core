db.tests.insertOne({
  "category": "linuxplus",
  "testId": 3,
  "testName": "CompTIA Linux+ (XK0-005) Practice Test #3 (Easy)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "A system administrator needs to identify which process is consuming the most disk I/O. Which command should they use?",
      "options": [
        "iotop",
        "iostat",
        "vmstat",
        "df -h"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`iotop` displays real-time disk I/O usage per process. `iostat` provides general disk activity statistics but does not isolate processes. `vmstat` monitors system performance but lacks process-specific details, and `df -h` reports filesystem usage, not process activity.",
      "examTip": "Use `iotop -o` to display only processes actively using disk I/O."
    },
    {
      "id": 2,
      "question": "Which of the following commands will display the most detailed per-core CPU statistics on a Linux system?",
      "options": [
        "mpstat -P ALL",
        "top",
        "lscpu",
        "cat /proc/cpuinfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`mpstat -P ALL` provides per-core CPU usage statistics. `top` shows live CPU activity but not per-core breakdowns, `lscpu` provides architecture details, and `/proc/cpuinfo` lists CPU specifications rather than usage statistics.",
      "examTip": "Use `mpstat` from the `sysstat` package for detailed CPU performance analysis."
    },
    {
      "id": 3,
      "question": "  You have configured a software RAID1 setup on two drives. The array appears functional, but upon reboot, the system occasionally complains that one drive is ‘missing’ from the array. You verify that both disks are healthy. What is the NEXT logical action to diagnose this intermittent issue?",
      "options": [
        "Temporarily disable the RAID by editing /etc/fstab and then inspect the drives individually with badblocks.",
        "Check the initramfs configuration to ensure RAID modules are included and rebuild the initramfs if necessary.",
        "Run mdadm --stop /dev/md0, power cycle the server, then recreate the array from scratch using mdadm --create.",
        "Configure a systemd service that forces a resync on every boot using mdadm --assemble --scan."
      ],
      "correctAnswerIndex": 1,
      "explanation": "An intermittent ‘missing drive’ error on boot often indicates the RAID modules or configuration aren't loaded early enough by the initramfs. Confirm that your RAID drivers and mdadm.conf are integrated into initramfs. Rebuilding it ensures the system properly recognizes all RAID members at startup.",
      "examTip": "RAID arrays must be recognized and assembled during early boot stages. If modules or config are absent from initramfs, disks may appear ‘missing’ even if physically healthy."
    },
    {
      "id": 4,
      "question": "Which file should be modified to set system-wide environment variables that apply to all users at login?",
      "options": [
        "/etc/environment",
        "/etc/profile",
        "~/.bashrc",
        "~/.profile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/environment` is the recommended file for setting global environment variables that apply to all users. `/etc/profile` affects interactive shells but not non-interactive sessions, while `~/.bashrc` and `~/.profile` apply only to individual users.",
      "examTip": "Use `printenv` to verify applied environment variables in a session."
    },
    {
      "id": 5,
      "question": "A user wants to ensure that new files created in `/shared` inherit the group ownership of the directory. Which command should be used?",
      "options": [
        "chmod g+s /shared",
        "chown -R :groupname /shared",
        "setfacl -m d:g:groupname:rwx /shared",
        "umask 002"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chmod g+s /shared` enables the `setgid` bit, ensuring that new files inherit the parent directory’s group ownership. `chown` changes ownership but does not enforce inheritance, `setfacl` modifies ACLs, and `umask` affects default permissions but not group inheritance.",
      "examTip": "Use `ls -ld /shared` to verify the `setgid` bit is applied (`drwxrws---`)."
    },
    {
      "id": 6,
      "question": "A Linux administrator needs to find all files named `config.yaml` under `/etc`, including subdirectories. Which command should they use?",
      "options": [
        "find /etc -type f -name 'config.yaml'",
        "locate /etc/config.yaml",
        "grep -r 'config.yaml' /etc",
        "ls -R /etc | grep 'config.yaml'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find /etc -type f -name 'config.yaml'` recursively searches for files named `config.yaml` under `/etc`. `locate` depends on an updated database, `grep` searches file contents rather than names, and `ls -R | grep` is inefficient.",
      "examTip": "Use `find /path -iname 'name'` for case-insensitive searches."
    },
    {
      "id": 7,
      "question": "Which command will show the size of all directories under `/var/log` in human-readable format?",
      "options": [
        "du -sh /var/log/*",
        "df -h /var/log",
        "ls -lh /var/log",
        "stat -c %s /var/log/*"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh /var/log/*` summarizes disk usage for each directory. `df -h` shows overall filesystem usage, `ls -lh` lists individual file sizes but does not sum them, and `stat` returns file sizes without summarizing directories.",
      "examTip": "Use `du -sh * | sort -hr` to find the largest directories quickly."
    },
    {
      "id": 8,
      "question": "Which command would you use to identify which process is consuming the most CPU resources in real-time?",
      "options": [
        "top",
        "ps aux --sort=-%cpu",
        "htop",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ps aux --sort=-%cpu` sorts processes by CPU usage, making it the best command for identifying high-CPU processes. While `top` and `htop` provide real-time monitoring, `ps` gives a clearer snapshot of CPU-intensive processes.",
      "examTip": "Use `htop` for an interactive, color-coded view of system resource usage."
    },
    {
      "id": 9,
      "question": "A Linux administrator needs to identify the default gateway for a server. Which command should they run?",
      "options": [
        "ip route show default",
        "netstat -rn",
        "route -n",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip route show default` is the modern command to check the system’s default gateway. `netstat -rn` and `route -n` also display routing information, but `ip` is the preferred tool on modern Linux systems.",
      "examTip": "Use `ip route get 8.8.8.8` to determine which gateway is used for a specific destination."
    },
    {
      "id": 10,
      "question": "Which of the following commands will reload the Udev rules without rebooting the system?",
      "options": [
        "udevadm control --reload-rules",
        "systemctl restart udev",
        "modprobe -r udev && modprobe udev",
        "service udev reload"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`udevadm control --reload-rules` applies Udev rule changes immediately. `systemctl restart udev` may work but is not always necessary, `modprobe` manages kernel modules rather than Udev, and `service` is deprecated on modern systems.",
      "examTip": "After reloading Udev rules, run `udevadm trigger` to apply them immediately."
    },
    {
      "id": 11,
      "question": "Which command will create a new user named `developer` with a custom home directory at `/srv/devhome`?",
      "options": [
        "useradd -m -d /srv/devhome developer",
        "adduser --home /srv/devhome developer",
        "usermod -d /srv/devhome developer",
        "passwd developer"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`useradd -m -d /srv/devhome developer` creates the user and assigns a custom home directory. `usermod` modifies existing users, and `passwd` sets passwords, not home directories.",
      "examTip": "Use `useradd -m -d <dir> <user>` to specify a custom home directory."
    },
    {
      "id": 12,
      "question": "A user reports that they cannot execute a script named `deploy.sh` despite having execute permissions. What is the MOST likely cause?",
      "options": [
        "The script has an incorrect or missing shebang line.",
        "The script is owned by another user.",
        "The execute permission is missing on `/bin/bash`.",
        "The script is located in a non-executable filesystem."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If a script has execute permissions but does not run, it likely has an incorrect or missing shebang (`#!/bin/bash`), preventing it from executing properly.",
      "examTip": "Run `head -1 deploy.sh` to check for a valid shebang line."
    },
    {
      "id": 13,
      "question": "You need to temporarily grant a junior admin the ability to manage network interfaces without giving them root privileges. Which step addresses this requirement?",
      "options": [
        "Include the user in the root group to inherit complete root-level permissions over network settings.",
        "Edit /etc/passwd so that the user’s shell is /sbin/nologin, restricting them from any administrative commands.",
        "Set a SUID bit on /sbin/ifconfig to allow non-root execution of network configuration commands.",
        "Use visudo to add a rule granting only network-related commands, such as /sbin/ifdown and /sbin/ifup, without full sudo access."
      ],
      "correctAnswerIndex": 3,
      "explanation": "By editing /etc/sudoers using visudo and specifying explicit commands, you can restrict the user to only those operations needed for managing network interfaces, avoiding a blanket root group addition or insecure SUID-based approaches.",
      "examTip": "Always apply principle of least privilege: tailor sudo rules to just the commands required rather than giving broad privileges."
    },
    {
      "id": 14,
      "question": "Which command will remove a Logical Volume (LV) named `data` from the volume group `vg01`?",
      "options": [
        "lvremove /dev/vg01/data",
        "vgremove /dev/vg01/data",
        "pvremove /dev/vg01/data",
        "lvdelete /dev/vg01/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lvremove` deletes a logical volume. `vgremove` removes entire volume groups, `pvremove` works on physical volumes, and `lvdelete` is not a valid command.",
      "examTip": "Ensure the volume is unmounted before using `lvremove`."
    },
    {
      "id": 15,
      "question": "Which command will safely clear the contents of a log file named `/var/log/syslog` without deleting the file itself?",
      "options": [
        "truncate -s 0 /var/log/syslog",
        "> /var/log/syslog",
        "rm -f /var/log/syslog",
        "echo '' > /var/log/syslog"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`truncate -s 0` clears a file while preserving its inode, ensuring applications can continue logging. `>` and `echo` also clear files but are less explicit, while `rm` deletes the file entirely.",
      "examTip": "Use `truncate -s 0` for clearing logs without affecting running services."
    },
    {
      "id": 16,
      "question": "Which of the following commands will permanently disable the `httpd` service on a systemd-based system?",
      "options": [
        "systemctl disable --now httpd",
        "systemctl stop httpd",
        "systemctl mask httpd",
        "systemctl unmask httpd"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`systemctl mask httpd` prevents the service from being started, even manually. `disable` stops it from auto-starting but allows manual starts, `stop` only stops it temporarily, and `unmask` reverses masking.",
      "examTip": "Use `systemctl is-enabled httpd` to check if a service is disabled."
    },
    {
      "id": 17,
      "question": "A Linux administrator needs to check which ports are actively listening for incoming connections. Which command should they use?",
      "options": [
        "ss -tuln",
        "netstat -an",
        "lsof -i",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ss -tuln` is the recommended command for listing listening ports. `netstat -an` also works, but `ss` is faster. `lsof -i` lists open network connections but does not focus on listening ports.",
      "examTip": "Use `ss -tulnp` to include process names associated with listening ports."
    },
    {
      "id": 18,
      "question": "Which command displays detailed information about a specific loaded kernel module?",
      "options": [
        "modinfo <module>",
        "lsmod | grep <module>",
        "modprobe -r <module>",
        "insmod <module>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`modinfo <module>` provides detailed information about a kernel module, including parameters and dependencies. `lsmod` lists loaded modules, `modprobe -r` removes modules, and `insmod` loads modules manually.",
      "examTip": "Use `modinfo <module>` before removing or modifying kernel modules."
    },
    {
      "id": 19,
      "question": "Which command will list all active SSH connections to a Linux server?",
      "options": [
        "ss -tuna | grep :22",
        "netstat -tnpa | grep sshd",
        "who",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can help identify active SSH connections. `ss -tuna` and `netstat -tnpa` show listening and active network connections, while `who` lists logged-in users, including SSH sessions.",
      "examTip": "Use `w` to see additional session details for logged-in users."
    },
    {
      "id": 20,
      "question": "Which command displays the default runlevel or target for a systemd-based Linux distribution?",
      "options": [
        "systemctl get-default",
        "runlevel",
        "systemctl list-units --type=target",
        "who -r"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl get-default` shows the system’s default target (runlevel equivalent) in systemd-based distributions. `runlevel` and `who -r` apply to SysVinit, while `list-units --type=target` lists all targets but does not show the default.",
      "examTip": "Use `systemctl set-default <target>` to change the default boot target."
    },
    {
      "id": 21,
      "question": "A Linux administrator needs to find all `.conf` files modified within the last 7 days under `/etc`. Which command should they use?",
      "options": [
        "find /etc -name '*.conf' -mtime -7",
        "ls -lt /etc/*.conf",
        "grep -rl '*.conf' /etc",
        "stat -c '%y' /etc/*.conf | grep '7 days ago'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find /etc -name '*.conf' -mtime -7` searches for files with a `.conf` extension modified in the last 7 days. `ls -lt` sorts by modification time but does not filter by days, `grep -rl` searches file contents, and `stat` does not efficiently filter by time.",
      "examTip": "Use `-mtime` with `find` to filter files modified within a specific timeframe."
    },
    {
      "id": 22,
      "question": "Which command will permanently set the default target to multi-user mode on a systemd-based system?",
      "options": [
        "systemctl set-default multi-user.target",
        "systemctl isolate multi-user.target",
        "runlevel 3",
        "init 3"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl set-default multi-user.target` configures the system to boot into multi-user mode by default. `isolate` switches the current session but does not persist after reboot, while `runlevel` and `init` apply to SysVinit systems.",
      "examTip": "Use `systemctl get-default` to verify the current default target."
    },
    {
      "id": 23,
      "question": "A Linux system is failing to mount an NFS share during boot. After the system is fully up, a manual mount works fine. System logs show a network service dependency error at boot time. Which action addresses the dependency issue so the NFS mount succeeds on startup?",
      "options": [
        "Add the _netdev option to the NFS entry in /etc/fstab so the mount waits for network services.",
        "Disable NetworkManager and revert to static configuration in /etc/sysconfig/network-scripts/ifcfg-<interface>.",
        "Use systemctl mask nfs-server to force the NFS service to remain inactive until manual mount is triggered.",
        "Add a pre-up script in /etc/network/interfaces to forcibly mount all NFS shares once the interface is up."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The _netdev option in /etc/fstab ensures that the filesystem mounting will be delayed until the network is fully operational. This addresses the startup dependency so the system doesn’t attempt an NFS mount before the network is ready.",
      "examTip": "NFS mounts can fail at boot if network services are not yet available. _netdev ensures proper ordering of dependencies."
    },
    {
      "id": 24,
      "question": "Which command will display all open TCP and UDP ports on a Linux system?",
      "options": [
        "ss -tunlp",
        "netstat -tulnp",
        "lsof -i",
        "All of the above"
      ],
      "correctAnswerIndex": 2,
      "explanation": "`ss -tunlp` and `netstat -tulnp` both show open ports, but `lsof -i` lists all network-related open files, making it more comprehensive.",
      "examTip": "Use `ss` instead of `netstat` on modern distributions, as `netstat` is deprecated."
    },
    {
      "id": 25,
      "question": "Which of the following is the correct syntax to add a new software repository on a Debian-based system?",
      "options": [
        "echo 'deb http://repo-url/ stable main' | sudo tee /etc/apt/sources.list.d/custom.list",
        "yum-config-manager --add-repo http://repo-url/",
        "dnf config-manager --add-repo http://repo-url/",
        "zypper addrepo http://repo-url/"
      ],
      "correctAnswerIndex": 0,
      "explanation": "On Debian-based systems, repository entries are added to `/etc/apt/sources.list.d/`. `yum` and `dnf` are used in RHEL-based distributions, and `zypper` is used in openSUSE.",
      "examTip": "After adding a repository, run `sudo apt update` to refresh package lists."
    },
    {
      "id": 26,
      "question": "Which command will display detailed CPU information, including model name and clock speed?",
      "options": [
        "lscpu",
        "cat /proc/cpuinfo",
        "dmidecode -t processor",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide CPU information: `lscpu` summarizes CPU architecture, `/proc/cpuinfo` gives per-core details, and `dmidecode` retrieves BIOS-level CPU details.",
      "examTip": "Use `lscpu` for quick summaries and `/proc/cpuinfo` for per-core specifications."
    },
    {
      "id": 27,
      "question": "A system administrator needs to determine which processes are using the most memory. Which command should they use?",
      "options": [
        "ps aux --sort=-%mem",
        "top",
        "free -m",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ps aux --sort=-%mem` lists processes sorted by memory usage. `top` shows live memory usage, but `ps` provides a clearer view of memory-hungry processes. `free -m` shows overall memory statistics but not per-process usage.",
      "examTip": "Use `htop` for a real-time interactive view of memory and CPU usage."
    },
    {
      "id": 28,
      "question": "Which command will list all user accounts on a Linux system?",
      "options": [
        "cut -d: -f1 /etc/passwd",
        "getent passwd",
        "awk -F: '{print $1}' /etc/passwd",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All commands retrieve user account names: `cut` extracts usernames, `getent passwd` queries the user database, and `awk` filters `/etc/passwd` for usernames.",
      "examTip": "Use `getent passwd | grep username` to check if a specific user exists."
    },
    {
      "id": 29,
      "question": "Which command will reload the SSH service without disrupting active connections?",
      "options": [
        "systemctl reload sshd",
        "systemctl restart sshd",
        "kill -HUP $(pidof sshd)",
        "service sshd restart"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl reload sshd` applies configuration changes without terminating active SSH sessions. `restart` would disconnect users, `kill -HUP` works but is a lower-level alternative, and `service sshd restart` is deprecated on modern systems.",
      "examTip": "Use `sshd -t` before reloading to validate SSH configuration syntax."
    },
    {
      "id": 30,
      "question": "Which command will display the full path of an executable file associated with a command?",
      "options": [
        "which",
        "whereis",
        "type",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`whereis` shows the binary, source, and manual locations of a command. `which` finds the first executable in `PATH`, and `type` reveals how the shell interprets a command.",
      "examTip": "Use `command -v` for an alternative way to check command locations."
    },
    {
      "id": 31,
      "question": "Which of the following commands will create a new partition on a GPT-formatted disk?",
      "options": [
        "parted /dev/sdX mkpart",
        "fdisk /dev/sdX",
        "mkfs.ext4 /dev/sdX",
        "lsblk --create /dev/sdX"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`parted` is the recommended tool for managing GPT partitions. `fdisk` is typically used for MBR partitions, `mkfs.ext4` formats an existing partition but does not create one, and `lsblk` is used to list block devices, not modify them.",
      "examTip": "Use `gdisk` as an alternative tool for managing GPT partitions."
    },
    {
      "id": 32,
      "question": "Which command allows you to verify the integrity of installed RPM packages on a Red Hat-based system?",
      "options": [
        "rpm -Va",
        "yum verify",
        "dnf check-integrity",
        "rpm --checksig"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`rpm -Va` checks all installed RPM packages for integrity issues. `rpm --checksig` verifies package signatures but does not check file integrity. `yum verify` and `dnf check-integrity` are not valid commands.",
      "examTip": "Use `rpm -Va | grep missing` to check for missing files."
    },
    {
      "id": 33,
      "question": "You suspect a GRUB2 misconfiguration after a kernel update. The system fails to load the new kernel, booting only the old one. Which single command will regenerate the GRUB2 config file to include the new kernel entries?",
      "options": [
        "grub2-install /dev/sda",
        "grub2-set-default 0",
        "update-grub",
        "grub2-mkconfig -o /boot/grub2/grub.cfg"
      ],
      "correctAnswerIndex": 3,
      "explanation": "On many distributions (particularly RPM-based), grub2-mkconfig -o /boot/grub2/grub.cfg is the standard approach to regenerate the grub.cfg with updated kernel entries. The command 'update-grub' is more common in Debian-based systems, but might not exist on others.",
      "examTip": "Be mindful of distro-specific commands: RHEL/Fedora/CentOS use grub2-mkconfig, whereas Debian/Ubuntu typically use update-grub."
    },
    {
      "id": 34,
      "question": "Which command would you use to determine which process is holding a file open, preventing its deletion?",
      "options": [
        "lsof | grep <filename>",
        "ps aux | grep <filename>",
        "stat <filename>",
        "lsattr <filename>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof` lists open files and the processes using them. `ps aux` finds running processes but does not identify file locks, `stat` shows file metadata, and `lsattr` displays file attributes.",
      "examTip": "Use `fuser <filename>` as an alternative to check which process is using a file."
    },
    {
      "id": 35,
      "question": "Which file stores user account expiration policies on a Linux system?",
      "options": [
        "/etc/login.defs",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/default/useradd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/login.defs` defines system-wide user account policies, including password aging and expiration. `/etc/shadow` stores encrypted passwords, `/etc/passwd` lists user accounts, and `/etc/default/useradd` controls default settings for new users.",
      "examTip": "Use `chage -l <user>` to check expiration details for a specific user."
    },
    {
      "id": 36,
      "question": "Which of the following commands displays the SELinux enforcement mode?",
      "options": [
        "getenforce",
        "sestatus",
        "ls -Z",
        "setenforce"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`getenforce` returns the SELinux status (`Enforcing`, `Permissive`, or `Disabled`). `sestatus` provides more details, `ls -Z` shows security contexts, and `setenforce` is used to change modes but does not display the current status.",
      "examTip": "Use `sestatus` for a full SELinux status report, including policy details."
    },
    {
      "id": 37,
      "question": "Which command will display the last 50 lines of a log file and continue showing new lines as they are appended?",
      "options": [
        "tail -n 50 -f /var/log/syslog",
        "head -n 50 /var/log/syslog",
        "less +F /var/log/syslog",
        "cat /var/log/syslog | tail -n 50"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tail -n 50 -f` displays the last 50 lines and continuously updates as new lines are added. `head -n 50` only shows the first 50 lines, `less +F` follows changes but behaves differently, and piping `cat` to `tail` is inefficient.",
      "examTip": "Use `tail -f` for real-time log monitoring and troubleshooting."
    },
    {
      "id": 38,
      "question": "A system administrator wants to schedule a one-time task to run at 3:00 PM tomorrow. Which command should they use?",
      "options": [
        "echo '/path/to/script.sh' | at 15:00 tomorrow",
        "crontab -e",
        "systemctl schedule script.sh 15:00 tomorrow",
        "nohup /path/to/script.sh &"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The `at` command schedules one-time jobs at a specified time. `crontab -e` is used for recurring jobs, `systemctl schedule` is not a valid command, and `nohup` runs a command persistently but does not schedule it.",
      "examTip": "Use `atq` to view pending `at` jobs and `atrm <jobID>` to remove a scheduled job."
    },
    {
      "id": 39,
      "question": "Which command would you use to create a compressed archive named `backup.tar.gz` of the `/home` directory?",
      "options": [
        "tar -czvf backup.tar.gz /home",
        "tar -xzvf backup.tar.gz /home",
        "gzip -c /home > backup.tar.gz",
        "zip -r backup.tar.gz /home"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`tar -czvf` creates a compressed archive (`-c` for create, `-z` for gzip, `-v` for verbose, `-f` to specify a filename). `-x` is used for extraction, `gzip -c` compresses a single file, and `zip -r` is used for `.zip` files, not `.tar.gz`.",
      "examTip": "Remember `tar` options: `-c` (create), `-x` (extract), `-z` (gzip), `-j` (bzip2)."
    },
    {
      "id": 40,
      "question": "Which command will display all scheduled cron jobs for a specific user?",
      "options": [
        "crontab -l -u <username>",
        "cron -l <username>",
        "systemctl list-timers <username>",
        "ls /etc/cron.d/<username>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`crontab -l -u <username>` lists the cron jobs for a specific user. `cron -l` is not a valid command, `systemctl list-timers` lists systemd timers, and `/etc/cron.d/` contains system-wide cron jobs but does not list user-specific ones.",
      "examTip": "Use `crontab -e -u <username>` to edit a specific user’s cron jobs."
    },
    {
      "id": 41,
      "question": "Which of the following commands will display a list of all loaded kernel modules?",
      "options": [
        "lsmod",
        "modinfo",
        "modprobe -l",
        "insmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsmod` lists all currently loaded kernel modules. `modinfo` provides details about a specific module, `modprobe -l` lists available modules but does not display which ones are loaded, and `insmod` manually inserts a module.",
      "examTip": "Use `lsmod | grep <module>` to check if a specific module is loaded."
    },
    {
      "id": 42,
      "question": "A user is unable to write to a file they own. What is the MOST likely reason?",
      "options": [
        "The file has the immutable attribute set.",
        "The user does not have execute permissions on the directory.",
        "The file is owned by root.",
        "The user’s shell does not support write operations."
      ],
      "correctAnswerIndex": 0,
      "explanation": "If a file has the immutable attribute set (`chattr +i`), even the owner cannot modify it. Lack of execute permissions on a directory prevents traversal, but not writing to an existing file. File ownership does not matter if permissions allow writing, and shell limitations are unrelated.",
      "examTip": "Use `lsattr filename` to check if a file has immutable attributes set."
    },
    {
      "id": 43,
      "question": "Match each iptables chain to its primary purpose. Which mapping is correct?\n\nA) INPUT, B) OUTPUT, C) FORWARD\n\n1) Manages traffic leaving the system.\n2) Controls packets routed through the system to other networks.\n3) Governs incoming packets destined for the local machine.\n\nChoose the set [A->?, B->?, C->?].",
      "options": [
        "A->3, B->2, C->1",
        "A->1, B->3, C->2",
        "A->3, B->1, C->2",
        "A->2, B->1, C->3"
      ],
      "correctAnswerIndex": 2,
      "explanation": "INPUT handles packets entering the host, OUTPUT handles packets generated locally leaving the host, and FORWARD handles traffic passing through the host. Therefore, the correct mapping is [A->3, B->1, C->2].",
      "examTip": "Different iptables chains target distinct traffic directions. Understand which chain is used for local traffic vs. transit traffic."
    },
    {
      "id": 44,
      "question": "Which of the following commands will create a new filesystem on a partition?",
      "options": [
        "mkfs.ext4 /dev/sdX1",
        "fdisk /dev/sdX",
        "mount /dev/sdX1 /mnt",
        "fsck /dev/sdX1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`mkfs.ext4 /dev/sdX1` creates an ext4 filesystem on the specified partition. `fdisk` is used for partitioning, `mount` attaches an existing filesystem, and `fsck` checks filesystem integrity.",
      "examTip": "Use `mkfs -t ext4 /dev/sdX1` for a filesystem type-independent command."
    },
    {
      "id": 45,
      "question": "Which command will list all systemd services along with their current states?",
      "options": [
        "systemctl list-units --type=service",
        "systemctl list-services",
        "systemctl list-running",
        "service --status-all"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-units --type=service` lists all systemd services with their statuses. `systemctl list-services` is not a valid command, `list-running` shows only active services, and `service --status-all` applies to SysVinit systems.",
      "examTip": "Use `systemctl --failed` to list only failed services."
    },
    {
      "id": 46,
      "question": "A system administrator wants to determine which user last modified a file. Which command should they use?",
      "options": [
        "auditctl -w /path/to/file -p wa",
        "ls -lt /path/to/file",
        "stat /path/to/file",
        "getfacl /path/to/file"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`auditctl -w /path/to/file -p wa` enables auditing for file modifications, allowing tracking of which user last modified the file. `ls -lt` shows modification times but not the user, `stat` provides metadata, and `getfacl` lists access control details.",
      "examTip": "Use `ausearch -f /path/to/file` to view audit logs for a specific file."
    },
    {
      "id": 47,
      "question": "Which command will display a real-time stream of system log messages on a systemd-based Linux system?",
      "options": [
        "journalctl -f",
        "tail -f /var/log/syslog",
        "dmesg -w",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can display real-time logs. `journalctl -f` follows systemd journal logs, `tail -f` monitors syslog files, and `dmesg -w` follows kernel messages.",
      "examTip": "Use `journalctl -xe` to see detailed logs, including errors and warnings."
    },
    {
      "id": 48,
      "question": "Which of the following commands will remove all untracked files from a Git repository?",
      "options": [
        "git clean -df",
        "git reset --hard",
        "git rm --cached",
        "git checkout HEAD"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`git clean -df` removes untracked files and directories. `git reset --hard` resets tracked files, `git rm --cached` removes a file from staging without deleting it, and `git checkout HEAD` resets working directory changes but does not remove untracked files.",
      "examTip": "Use `git clean -n` first to preview which files will be deleted."
    },
    {
      "id": 49,
      "question": "Which command will display detailed memory usage, including swap utilization, on a Linux system?",
      "options": [
        "free -m",
        "vmstat -s",
        "top",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide memory usage details. `free -m` shows overall memory and swap, `vmstat -s` provides a breakdown, and `top` gives real-time monitoring.",
      "examTip": "Use `free -h` for human-readable memory statistics."
    },
    {
      "id": 50,
      "question": "Which command will forcefully terminate a process with PID 1234?",
      "options": [
        "kill -9 1234",
        "kill -15 1234",
        "pkill 1234",
        "killall 1234"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`kill -9 1234` sends the SIGKILL signal, terminating the process immediately. `kill -15` attempts a graceful termination, `pkill` searches for processes by name, and `killall` terminates all instances of a process name.",
      "examTip": "Use `kill -15` first before resorting to `kill -9` to allow proper cleanup."
    },
    {
      "id": 51,
      "question": "Which of the following commands will display the UUID of all block devices?",
      "options": [
        "blkid",
        "lsblk -f",
        "df -T",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`blkid` retrieves block device attributes, including UUIDs. `lsblk -f` also shows filesystem info but does not always include UUIDs, `df -T` lists filesystem types, and `mount -l` shows mounted filesystems.",
      "examTip": "Use `blkid | grep UUID` to filter output specifically for UUIDs."
    },
    {
      "id": 52,
      "question": "Which command is used to list open network connections, including their associated processes?",
      "options": [
        "ss -tulnp",
        "netstat -anp",
        "lsof -i",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`ss -tulnp` is the modern command for displaying open network connections and listening ports. `netstat -anp` does the same but is deprecated, while `lsof -i` shows network-related open files.",
      "examTip": "Use `ss -tunap` for detailed network connection analysis."
    },
    {
      "id": 53,
      "question": "You need to expand an existing LVM logical volume by 5GB in a VG (Volume Group) that has sufficient free space. Which single command achieves this expansion (assuming /dev/vgdata/lvdata is the LV and /mountpoint is already mounted)?",
      "options": [
        "lvcreate -n lvdata -L +5G /dev/vgdata && resize2fs /dev/vgdata/lvdata",
        "lvextend -L +5G /dev/vgdata/lvdata && resize2fs /dev/vgdata/lvdata",
        "vgextend /dev/vgdata -L +5G && resize2fs /dev/vgdata/lvdata",
        "pvresize --setphysicalvolumesize +5G /dev/vgdata/lvdata && resize2fs /dev/vgdata/lvdata"
      ],
      "correctAnswerIndex": 1,
      "explanation": "To increase an existing LV by 5GB, lvextend -L +5G /dev/vgdata/lvdata is used, followed by an appropriate filesystem resize command (e.g., resize2fs) to expand the filesystem. The other commands do not correctly address a simple LV size expansion in an existing volume group.",
      "examTip": "Always remember to resize the filesystem after extending the logical volume to ensure the OS sees the updated capacity."
    },
    {
      "id": 54,
      "question": "A user needs to copy a directory and its contents while preserving file permissions and symbolic links. Which command should they use?",
      "options": [
        "cp -a /source /destination",
        "cp -r /source /destination",
        "rsync /source /destination",
        "tar -cf backup.tar /source"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`cp -a` (archive mode) copies directories while preserving permissions, ownership, and symbolic links. `cp -r` copies directories but does not maintain attributes, `rsync` requires additional flags for preservation, and `tar` creates archives rather than copying files.",
      "examTip": "Use `rsync -av /source /destination` for an alternative with progress tracking."
    },
    {
      "id": 55,
      "question": "Which of the following tools is used to securely erase a storage device?",
      "options": [
        "shred",
        "dd if=/dev/zero of=/dev/sdX",
        "wipe",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can securely erase data. `shred` overwrites files multiple times, `dd` writes zeroes, and `wipe` performs secure disk erasure.",
      "examTip": "Use `shred -n 3 -z filename` for a secure multi-pass wipe."
    },
    {
      "id": 56,
      "question": "Which command will display scheduled systemd timers?",
      "options": [
        "systemctl list-timers",
        "crontab -l",
        "atq",
        "systemctl list-tasks"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`systemctl list-timers` lists scheduled systemd timers. `crontab -l` lists user cron jobs, `atq` displays `at` jobs, and `systemctl list-tasks` is not a valid command.",
      "examTip": "Use `systemctl list-timers --all` to include inactive timers."
    },
    {
      "id": 57,
      "question": "Which of the following directories typically contains kernel modules?",
      "options": [
        "/lib/modules/",
        "/etc/modules/",
        "/usr/lib/kernel/",
        "/boot/modules/"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Kernel modules are stored in `/lib/modules/`. `/etc/modules/` contains a list of modules to load at boot, `/usr/lib/kernel/` is not a standard directory, and `/boot/modules/` is not used for module storage.",
      "examTip": "Use `modinfo <module>` to check details about a specific module."
    },
    {
      "id": 58,
      "question": "Which command is used to display detailed system information, including hardware and BIOS details?",
      "options": [
        "dmidecode",
        "lscpu",
        "lsblk",
        "cat /proc/meminfo"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`dmidecode` retrieves detailed hardware information, including BIOS, CPU, and memory details. `lscpu` focuses on CPU information, `lsblk` lists block devices, and `/proc/meminfo` provides memory statistics but no hardware details.",
      "examTip": "Use `sudo dmidecode -t system` for full hardware information."
    },
    {
      "id": 59,
      "question": "Which of the following firewall management tools is the default on modern Red Hat-based distributions?",
      "options": [
        "firewalld",
        "iptables",
        "nftables",
        "ufw"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`firewalld` is the default firewall tool in Red Hat-based distributions. `iptables` is older, `nftables` is newer but not always default, and `ufw` is commonly used on Ubuntu-based systems.",
      "examTip": "Use `firewall-cmd --permanent --add-service=ssh` to allow SSH traffic permanently."
    },
    {
      "id": 60,
      "question": "Which command will display the total number of lines, words, and characters in a file named `document.txt`?",
      "options": [
        "wc document.txt",
        "cat document.txt | wc",
        "grep -c '' document.txt",
        "awk '{print NR}' document.txt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`wc` (word count) without any options displays the number of lines, words, and characters in a file. `cat | wc` is redundant, `grep -c ''` counts lines only, and `awk '{print NR}'` prints the line count.",
      "examTip": "Use `wc -l`, `wc -w`, or `wc -c` to count lines, words, or characters separately."
    },
    {
      "id": 61,
      "question": "A user wants to check which groups they are a member of. Which command should they use?",
      "options": [
        "groups",
        "id -G",
        "getent group | grep $USER",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands retrieve group membership information. `groups` shows a user’s groups, `id -G` displays group IDs, and `getent group | grep $USER` queries the system group database.",
      "examTip": "Use `id -Gn` to see group names instead of numerical GIDs."
    },
    {
      "id": 62,
      "question": "Which command will display all currently mounted filesystems?",
      "options": [
        "mount",
        "df -h",
        "lsblk -f",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`mount` lists all mounted filesystems, showing their source and mount points. `df -h` provides disk usage statistics, and `lsblk -f` lists block devices and their filesystem types.",
      "examTip": "Use `findmnt` for a tree-based view of mounted filesystems."
    },
    {
      "id": 63,
      "question": "Match the core systemd unit types with their purpose. Which single matching set is correct?\n\nA) service, B) socket, C) target, D) mount\n\n1) Abstract grouping of other units, often used for synchronization points.\n2) Manages network or IPC endpoints that activate on-demand services.\n3) Attaches a filesystem to a specific directory hierarchy location.\n4) Defines how and when a system daemon is run.\n\nSelect the matching format [A->?, B->?, C->?, D->?].",
      "options": [
        "A->2, B->1, C->3, D->4",
        "A->4, B->2, C->1, D->3",
        "A->1, B->3, C->2, D->4",
        "A->4, B->1, C->2, D->3"
      ],
      "correctAnswerIndex": 1,
      "explanation": "systemd unit types: service (.service) defines a system daemon, socket (.socket) manages listening sockets/ports, target (.target) groups or synchronizes units (like multi-user.target), and mount (.mount) points define filesystem mounting. Therefore, the correct match is [A->4, B->2, C->1, D->3].",
      "examTip": "Understanding systemd unit types is key to controlling how services start, how sockets trigger services, and how targets group multiple units."
    },
    {
      "id": 64,
      "question": "Which command is used to generate an SSH key pair for secure authentication?",
      "options": [
        "ssh-keygen",
        "openssl genrsa",
        "ssh-copy-id",
        "gpg --gen-key"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ssh-keygen` creates an SSH key pair. `openssl genrsa` generates an RSA key but is not specific to SSH, `ssh-copy-id` copies a key to a remote server, and `gpg --gen-key` is used for GPG encryption.",
      "examTip": "Use `ssh-keygen -t ed25519` for a more secure key type than RSA."
    },
    {
      "id": 65,
      "question": "Which file contains system-wide environment variable settings in a Linux system?",
      "options": [
        "/etc/environment",
        "/etc/profile",
        "~/.bashrc",
        "/etc/bashrc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/environment` is used for defining system-wide environment variables. `/etc/profile` and `/etc/bashrc` affect shell sessions, while `~/.bashrc` applies only to a specific user.",
      "examTip": "Run `printenv` to see currently active environment variables."
    },
    {
      "id": 66,
      "question": "Which of the following commands will list all open files associated with a specific process?",
      "options": [
        "lsof -p <PID>",
        "ps aux | grep <PID>",
        "netstat -nap | grep <PID>",
        "fdisk -l <PID>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`lsof -p <PID>` lists all open files associated with a specific process. `ps aux` shows process details but not open files, `netstat` displays network sockets, and `fdisk -l` is unrelated to processes.",
      "examTip": "Use `lsof +D /path/to/dir` to check open files in a directory."
    },
    {
      "id": 67,
      "question": "Which command allows an administrator to check user password expiration details?",
      "options": [
        "chage -l <username>",
        "passwd -S <username>",
        "cat /etc/shadow",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`passwd -S <username>` displays password status, including expiration info. `chage -l` lists detailed aging settings, and `/etc/shadow` contains password hashes but requires root access.",
      "examTip": "Use `chage -E <date> <username>` to manually set an expiration date."
    },
    {
      "id": 68,
      "question": "A system administrator needs to update the GRUB bootloader configuration. Which file should they modify?",
      "options": [
        "/etc/default/grub",
        "/boot/grub/grub.cfg",
        "/etc/grub.conf",
        "/boot/grub/menu.lst"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/default/grub` is the correct file to edit for GRUB configuration changes. `grub.cfg` is auto-generated, `grub.conf` is used in older GRUB versions, and `menu.lst` was used in GRUB Legacy.",
      "examTip": "Run `grub2-mkconfig -o /boot/grub2/grub.cfg` after modifying `/etc/default/grub`."
    },
    {
      "id": 69,
      "question": "Which command displays the amount of free and used memory in a human-readable format?",
      "options": [
        "free -h",
        "vmstat -s",
        "top",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`free -h` provides memory usage in a human-readable format. `vmstat -s` shows memory statistics, and `top` provides real-time monitoring.",
      "examTip": "Use `free -h` for quick memory checks and `vmstat 1 5` for real-time monitoring."
    },
    {
      "id": 70,
      "question": "A user needs to recursively change the ownership of all files in `/var/www` to the `webadmin` user and group. Which command should they use?",
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
      "id": 71,
      "question": "Which of the following commands will modify the default permissions for newly created files in a user's session?",
      "options": [
        "umask",
        "chmod",
        "chown",
        "setfacl"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`umask` sets default permissions for new files and directories in a session. `chmod` modifies existing file permissions, `chown` changes ownership, and `setfacl` manages access control lists (ACLs).",
      "examTip": "Use `umask 022` to ensure new directories get `755` permissions and files get `644`."
    },
    {
      "id": 72,
      "question": "Which command will display the routing table on a Linux system?",
      "options": [
        "ip route show",
        "netstat -r",
        "route -n",
        "All of the above"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ip route show` is the modern command for displaying routing tables. `netstat -r` and `route -n` are older alternatives but are still functional.",
      "examTip": "Use `ip route get <IP>` to check which route is used for a specific destination."
    },
    {
      "id": 73,
      "question": "A system administrator suspects that a process is consuming excessive network bandwidth and needs to identify and terminate it. What is the correct sequence of actions?",
      "options": [
        "1) ss -tunap 2) kill -9 <PID> 3) systemctl restart network",
        "1) netstat -tulnp 2) pkill -9 <process_name> 3) ifconfig eth0 down",
        "1) iftop 2) ps aux | grep <process> 3) kill <PID>",
        "1) lsof -i 2) kill <PID> 3) restart systemd-resolved"
      ],
      "correctAnswerIndex": 2,
      "explanation": "Using `iftop` first identifies high-bandwidth processes, `ps aux | grep <process>` confirms the process details, and `kill <PID>` terminates it. Other sequences contain unnecessary or incorrect steps such as `systemctl restart network` and `ifconfig eth0 down`.",
      "examTip": "Use `iftop` for live network traffic monitoring and `kill -9` only when necessary."
    },
    {
      "id": 74,
      "question": "Which of the following commands will list all scheduled cron jobs for a specific user?",
      "options": [
        "crontab -l -u <username>",
        "crontab -e <username>",
        "systemctl list-timers --user <username>",
        "ls /etc/cron.d/<username>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`crontab -l -u <username>` lists scheduled cron jobs for a user. `crontab -e` edits jobs but does not list them, `systemctl list-timers` shows systemd timers, and `ls /etc/cron.d/` lists system-wide jobs but not user-specific ones.",
      "examTip": "Use `crontab -r -u <username>` to remove all cron jobs for a user."
    },
    {
      "id": 75,
      "question": "Which command would you use to format a partition with the XFS filesystem?",
      "options": [
        "mkfs.xfs /dev/sdX1",
        "mkfs.ext4 /dev/sdX1",
        "mkswap /dev/sdX1",
        "fdisk /dev/sdX1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`mkfs.xfs` creates an XFS filesystem. `mkfs.ext4` formats as ext4, `mkswap` configures swap space, and `fdisk` is used for partitioning but does not create filesystems.",
      "examTip": "Use `xfs_repair` for checking and fixing XFS filesystems."
    },
    {
      "id": 76,
      "question": "Which command will display real-time CPU, memory, and system load statistics?",
      "options": [
        "top",
        "uptime",
        "vmstat",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide real-time system statistics. `top` shows CPU/memory usage, `uptime` displays load averages, and `vmstat` reports detailed performance metrics.",
      "examTip": "Use `htop` for an interactive version of `top` with color-coded statistics."
    },
    {
      "id": 77,
      "question": "Which command is used to manually load a kernel module into the Linux kernel?",
      "options": [
        "modprobe <module>",
        "insmod <module>",
        "lsmod <module>",
        "depmod <module>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`modprobe` is the preferred way to load kernel modules as it automatically resolves dependencies. `insmod` loads a module but does not handle dependencies, `lsmod` lists loaded modules, and `depmod` updates module dependencies.",
      "examTip": "Use `modinfo <module>` to see details about a specific kernel module."
    },
    {
      "id": 78,
      "question": "A system administrator needs to configure a persistent static IP address on a modern Linux system using NetworkManager. Which command should they use?",
      "options": [
        "nmcli con mod <connection> ipv4.address <IP>",
        "ifconfig <interface> <IP>",
        "ip addr add <IP>/<mask> dev <interface>",
        "netplan apply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`nmcli con mod <connection> ipv4.address <IP>` configures a persistent static IP for a NetworkManager-managed interface. Other options set temporary addresses.",
      "examTip": "Use `nmcli con show` to list active network connections before modifying them."
    },
    {
      "id": 79,
      "question": "Which directory typically contains system log files on a Linux system?",
      "options": [
        "/var/log",
        "/etc/log",
        "/usr/log",
        "/root/logs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/var/log` is the standard location for system logs. Other directories listed do not typically store logs.",
      "examTip": "Use `journalctl` for systemd-based logs and `tail -f /var/log/syslog` for real-time monitoring."
    },
    {
      "id": 80,
      "question": "Which command allows you to change the default shell for a user?",
      "options": [
        "chsh -s /bin/bash <username>",
        "usermod -s /bin/bash <username>",
        "passwd -s /bin/bash <username>",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`usermod -s` modifies a user’s default shell. `chsh -s` also works but requires the shell to be listed in `/etc/shells`. `passwd -s` does not modify shell settings.",
      "examTip": "Use `cat /etc/shells` to check available shells before changing a user’s default."
    },
    {
      "id": 81,
      "question": "Which command allows an administrator to check for disk errors on an ext4 filesystem?",
      "options": [
        "fsck /dev/sdX1",
        "e2fsck /dev/sdX1",
        "xfs_repair /dev/sdX1",
        "All of the above"
      ],
      "correctAnswerIndex": 1,
      "explanation": "`e2fsck` is specifically designed for ext2/ext3/ext4 filesystems. `fsck` is a general wrapper for filesystem checks, but `xfs_repair` applies only to XFS filesystems.",
      "examTip": "Use `fsck -n` to perform a dry run before making actual repairs."
    },
    {
      "id": 82,
      "question": "Which command is used to view the default shell of a specific user?",
      "options": [
        "grep <username> /etc/passwd",
        "echo $SHELL",
        "cat /etc/shells",
        "whoami --shell"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The default shell for a user is stored in `/etc/passwd`, which can be queried with `grep <username> /etc/passwd`. `$SHELL` shows the current user’s shell but not others’.",
      "examTip": "Use `chsh -s <shell> <username>` to change a user’s default shell."
    },
    {
      "id": 83,
      "question": "A Linux administrator needs to configure a new disk for use. What is the correct sequence of actions?",
      "options": [
        "1) fdisk /dev/sdX 2) mkfs.ext4 /dev/sdX1 3) mount /dev/sdX1 /mnt/data",
        "1) mkfs.ext4 /dev/sdX 2) mount /dev/sdX /mnt/data 3) fdisk /dev/sdX",
        "1) mount /dev/sdX1 /mnt/data 2) fdisk /dev/sdX 3) mkfs.ext4 /dev/sdX1",
        "1) fdisk /dev/sdX 2) mount /dev/sdX1 /mnt/data 3) mkfs.ext4 /dev/sdX1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The correct order is: (1) partition the disk with `fdisk`, (2) create a filesystem using `mkfs.ext4`, and (3) mount the partition. Other sequences incorrectly mount before formatting or use `mkfs` before partitioning.",
      "examTip": "Use `lsblk` to verify partitioning before formatting."
    },
    {
      "id": 84,
      "question": "A user accidentally deleted their `.bashrc` file. Which command will restore it to its default state?",
      "options": [
        "cp /etc/skel/.bashrc ~/",
        "touch ~/.bashrc",
        "echo '' > ~/.bashrc",
        "source ~/.bashrc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The default `.bashrc` file is stored in `/etc/skel/`. Copying it back restores the user’s configuration.",
      "examTip": "For system-wide configurations, modify `/etc/profile` instead of `.bashrc`."
    },
    {
      "id": 85,
      "question": "Which command is used to display kernel ring buffer messages?",
      "options": [
        "dmesg",
        "journalctl -k",
        "cat /var/log/kern.log",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide kernel log messages. `dmesg` shows kernel logs, `journalctl -k` retrieves them from the systemd journal, and `/var/log/kern.log` stores persistent logs on some systems.",
      "examTip": "Use `dmesg | grep error` to filter logs for potential issues."
    },
    {
      "id": 86,
      "question": "A user needs to verify the disk usage of all directories inside `/var`. Which command should they use?",
      "options": [
        "du -sh /var/*",
        "df -h /var",
        "ls -lh /var",
        "stat /var"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh /var/*` summarizes disk usage for all directories inside `/var`. `df -h` shows overall filesystem usage, `ls -lh` lists file sizes but does not summarize directories, and `stat` provides metadata for a single file or directory.",
      "examTip": "Use `du -sh * | sort -hr` to list the largest directories in descending order."
    },
    {
      "id": 87,
      "question": "Which command is used to check the current runlevel on a SysVinit-based system?",
      "options": [
        "runlevel",
        "systemctl get-default",
        "who -r",
        "init --show"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`runlevel` displays the previous and current runlevel. `systemctl get-default` applies to systemd, and `who -r` provides similar information but is less commonly used.",
      "examTip": "For systemd-based systems, use `systemctl get-default` instead."
    },
    {
      "id": 88,
      "question": "A system administrator wants to find all files larger than 1GB in `/var/log`. Which command should they use?",
      "options": [
        "find /var/log -type f -size +1G",
        "du -sh /var/log",
        "ls -lhS /var/log",
        "stat -c '%s' /var/log/* | awk '$1 > 1073741824'"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`find /var/log -type f -size +1G` locates all files larger than 1GB. `du -sh` shows overall directory size, `ls -lhS` sorts by size but does not filter, and `stat` requires additional scripting.",
      "examTip": "Use `find /path -size +100M` to find files larger than 100MB."
    },
    {
      "id": 89,
      "question": "Which command will allow a user to switch to the root account while preserving their current environment?",
      "options": [
        "sudo -s",
        "su -",
        "sudo -i",
        "su"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`sudo -s` starts a root shell while preserving the current environment. `su -` starts a full root session with root’s environment, `sudo -i` simulates a fresh root login, and `su` switches users but does not preserve the environment.",
      "examTip": "Use `sudo -s` when you need root access but want to keep your current environment."
    },
    {
      "id": 90,
      "question": "Which command is used to list all user accounts on a Linux system?",
      "options": [
        "cut -d: -f1 /etc/passwd",
        "getent passwd",
        "awk -F: '{print $1}' /etc/passwd",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All commands retrieve user account names. `cut` extracts usernames, `getent passwd` queries the user database, and `awk` filters `/etc/passwd` for usernames.",
      "examTip": "Use `getent passwd | grep username` to verify if a user exists."
    },
    {
      "id": 91,
      "question": "Which command will display all active listening ports and their associated processes?",
      "options": [
        "ss -tulnp",
        "netstat -tulnp",
        "lsof -i -P -n",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands can show active listening ports. `ss -tulnp` is the modern replacement for `netstat -tulnp`, while `lsof -i -P -n` lists open network connections.",
      "examTip": "Use `ss` instead of `netstat`, as `netstat` is deprecated in modern distributions."
    },
    {
      "id": 92,
      "question": "Which file should be modified to change the default permissions assigned to newly created files?",
      "options": [
        "/etc/login.defs",
        "~/.bashrc",
        "/etc/profile",
        "umask"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`/etc/login.defs` sets the default `umask` value for new users. `~/.bashrc` and `/etc/profile` modify environment variables, not default file permissions.",
      "examTip": "Default `umask` is typically `022`, resulting in `755` directories and `644` files."
    },
    {
      "id": 93,
      "question": "A Linux administrator needs to set up a persistent firewall rule to allow SSH traffic. What is the correct sequence of actions?",
      "options": [
        "1) firewall-cmd --permanent --add-service=ssh 2) firewall-cmd --reload",
        "1) iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2) service iptables save",
        "1) ufw allow 22/tcp 2) ufw enable",
        "1) nft add rule inet filter input tcp dport 22 accept 2) nft list ruleset"
      ],
      "correctAnswerIndex": 0,
      "explanation": "For `firewalld`, adding a rule permanently and reloading the firewall is the correct approach. `iptables` is older and may not persist across reboots unless saved manually.",
      "examTip": "Use `firewall-cmd --list-all` to verify firewall settings after changes."
    },
    {
      "id": 94,
      "question": "Which command will show the total size of all files and subdirectories within `/var/log`?",
      "options": [
        "du -sh /var/log",
        "df -h /var/log",
        "ls -lh /var/log",
        "stat /var/log"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`du -sh /var/log` provides a summary of total disk usage for the directory. `df -h` shows filesystem usage, `ls -lh` lists file sizes but does not sum them, and `stat` provides file metadata.",
      "examTip": "Use `du -sh * | sort -hr` to find the largest directories quickly."
    },
    {
      "id": 95,
      "question": "Which of the following commands will modify a user's password expiration settings?",
      "options": [
        "chage",
        "passwd",
        "usermod",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All commands can modify password expiration settings. `chage` is specifically for aging settings, `passwd` can force expiration, and `usermod` can change expiration policies.",
      "examTip": "Use `chage -l <username>` to check a user’s password expiration details."
    },
    {
      "id": 96,
      "question": "Which command will display detailed information about a kernel module, including its dependencies?",
      "options": [
        "modinfo <module>",
        "lsmod | grep <module>",
        "modprobe -l <module>",
        "depmod <module>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`modinfo` provides detailed information about a kernel module, including parameters and dependencies. `lsmod` lists loaded modules, `modprobe -l` lists available modules, and `depmod` updates dependency mappings.",
      "examTip": "Use `modinfo <module>` before loading or removing kernel modules."
    },
    {
      "id": 97,
      "question": "A user reports that their SSH session disconnects after a short period of inactivity. Which setting should be adjusted?",
      "options": [
        "ClientAliveInterval",
        "KeepAlive",
        "TCPKeepAlive",
        "IdleTimeout"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ClientAliveInterval` in `sshd_config` controls how often the server sends keepalive messages. `KeepAlive` is not a valid SSH option, `TCPKeepAlive` affects only TCP settings, and `IdleTimeout` does not exist in standard SSH configurations.",
      "examTip": "Set `ClientAliveInterval 300` and `ClientAliveCountMax 3` to prevent idle disconnects."
    },
    {
      "id": 98,
      "question": "Which command allows a user to run a program with elevated privileges without switching to the root account?",
      "options": [
        "sudo <command>",
        "su -c '<command>'",
        "pkexec <command>",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands allow executing commands with elevated privileges. `sudo` is the most common, `su -c` runs a command as root, and `pkexec` provides an alternative in some distributions.",
      "examTip": "Use `sudo -i` for a full root shell if multiple privileged commands are needed."
    },
    {
      "id": 99,
      "question": "Which command would you use to monitor system-wide CPU, memory, and disk I/O usage in real time?",
      "options": [
        "vmstat 1",
        "top",
        "iotop",
        "All of the above"
      ],
      "correctAnswerIndex": 3,
      "explanation": "All listed commands provide real-time system resource monitoring. `vmstat 1` reports CPU, memory, and I/O statistics, `top` shows process-level details, and `iotop` focuses on per-process disk I/O.",
      "examTip": "Use `htop` for a more user-friendly alternative to `top`."
    },
    {
      "id": 100,
      "question": "Which command will create a symbolic link named `shortcut` that points to `/var/log/syslog`?",
      "options": [
        "ln -s /var/log/syslog shortcut",
        "ln /var/log/syslog shortcut",
        "cp /var/log/syslog shortcut",
        "link /var/log/syslog shortcut"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`ln -s /var/log/syslog shortcut` creates a symbolic (soft) link. `ln` without `-s` creates a hard link, `cp` copies the file instead of linking it, and `link` is a lower-level command that works only for hard links.",
      "examTip": "Use `ls -l shortcut` to verify that a symbolic link was created correctly."
    }
  ]
});
