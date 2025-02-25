db.tests.insertOne({
  "category": "CompTIA Linux+ XK0-005",
  "testId": 3,
  "testName": "Practice Test #3 (Easy)",
  "xpPerCorrect": 15,
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
      "question": "**(PBQ)** A Linux administrator needs to configure firewall rules. Match each command with its function:",
      "options": [
        "1. `firewall-cmd --add-port=443/tcp`  ->  A. Temporarily allows traffic on port 443",
        "2. `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`  ->  B. Adds a rule to allow SSH traffic",
        "3. `ufw allow 80/tcp`  ->  C. Permits HTTP traffic using UFW",
        "4. `nft add rule inet filter input tcp dport 53 accept`  ->  D. Allows DNS queries using nftables"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`firewall-cmd` manages `firewalld`, `iptables` manipulates legacy firewall rules, `ufw` is Ubuntu’s simplified firewall interface, and `nft` configures `nftables`.",
      "examTip": "Use `firewall-cmd --runtime-to-permanent` to make `firewalld` rules persistent."
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
      "question": "**(PBQ)** A system administrator needs to monitor system performance. Match each command with the resource it monitors:",
      "options": [
        "1. `top`  ->  A. CPU and memory usage",
        "2. `iostat`  ->  B. Disk I/O statistics",
        "3. `vmstat`  ->  C. System-wide performance overview",
        "4. `netstat -i`  ->  D. Network interface statistics"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`top` shows CPU and memory usage, `iostat` reports disk I/O, `vmstat` provides system-wide metrics, and `netstat -i` displays network statistics.",
      "examTip": "Use `htop` for an interactive version of `top` and `iotop` for disk I/O per process."
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
      "question": "**(PBQ)** A Linux administrator needs to modify file permissions. Match each command with its function:",
      "options": [
        "1. `chmod 750 file.txt`  ->  A. Grants full access to the owner, read/execute to group",
        "2. `chown user:group file.txt`  ->  B. Changes the owner and group of a file",
        "3. `umask 022`  ->  C. Sets default file permissions for new files",
        "4. `setfacl -m u:user:r file.txt`  ->  D. Grants read permissions to a specific user"
      ],
      "correctAnswerIndex": 0,
      "explanation": "`chmod` modifies permissions, `chown` changes ownership, `umask` defines default permissions, and `setfacl` manages ACLs for fine-grained access control.",
      "examTip": "Use `ls -l` to verify permissions and `getfacl` to check ACL settings."
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
    }
  ]
});



