db.tests.insertOne({
  "category": "CompTIA Linux+ XK0-005",
  "testId": 1,
  "testName": "Practice Test #1 (Normal)",
  "xpPerCorrect": 10,
  "questions": [
    {
      "id": 1,
      "question": "Which directory under the Linux Filesystem Hierarchy Standard (FHS) typically contains essential system binaries required for the system to boot and run in single-user mode?",
      "options": [
        "/usr/bin",
        "/bin",
        "/sbin",
        "/opt"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The /bin directory contains essential binary executables needed during system boot and single-user mode operation. Unlike /usr/bin, it is always available even when other partitions are not mounted.",
      "examTip": "Remember: /bin and /sbin contain critical binaries required for system repair and basic operations."
    },
    {
      "id": 2,
      "question": "What is the FIRST step a Linux administrator should take when encountering a kernel panic after a recent kernel upgrade?",
      "options": [
        "Boot into an older kernel version from the GRUB menu.",
        "Reinstall the GRUB bootloader.",
        "Run the dracut command to rebuild initramfs.",
        "Check hardware components for failures."
      ],
      "correctAnswerIndex": 0,
      "explanation": "Booting into an older kernel version allows the administrator to regain system access and troubleshoot the cause of the kernel panic without affecting the new kernel files.",
      "examTip": "Always attempt to boot with a known good kernel before making major recovery changes."
    },
    {
      "id": 3,
      "question": "Which command would BEST display all PCI devices on a Linux system, including network cards and graphic adapters?",
      "options": [
        "lsusb",
        "dmidecode",
        "lspci",
        "lsscsi"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The lspci command lists all PCI devices, such as network cards, graphic adapters, and other PCI hardware. lsusb lists USB devices, while dmidecode shows BIOS/hardware info.",
      "examTip": "Use lspci for PCI devices, lsusb for USB, and lsscsi for storage devices connected via SCSI."
    },
    {
      "id": 4,
      "question": "Given a scenario where a user cannot access files on a newly added partition, which file is MOST LIKELY misconfigured and needs correction?",
      "options": [
        "/etc/fstab",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/fstab controls how and where filesystems are mounted during boot. If the partition isn't accessible, a misconfiguration here is the most likely cause.",
      "examTip": "Always verify /etc/fstab entries when mount issues occur, especially after adding new storage."
    },
    {
      "id": 5,
      "question": "Which of the following BEST describes the role of Logical Volume Manager (LVM) in Linux storage management?",
      "options": [
        "It enables encryption of storage volumes using LUKS.",
        "It allows flexible resizing and management of storage volumes without downtime.",
        "It provides RAID-level redundancy for storage devices.",
        "It offers network-based storage management for cloud systems."
      ],
      "correctAnswerIndex": 1,
      "explanation": "LVM allows administrators to dynamically resize, extend, and manage storage volumes without affecting the running system, providing flexibility that traditional partitions lack.",
      "examTip": "LVM is ideal for environments where storage needs may change; practice common commands like lvcreate, lvextend, and lvresize."
    },
    {
      "id": 6,
      "question": "Which RAID level provides redundancy by mirroring data across two disks, ensuring data availability even if one disk fails?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 mirrors data across two disks, providing redundancy and fault tolerance if a single disk fails. RAID 0 provides no redundancy, while RAID 5 and RAID 10 have different configurations.",
      "examTip": "RAID 1 = Mirroring; RAID 0 = Striping (no redundancy)."
    },
    {
      "id": 7,
      "question": "Which command should you use to safely unmount a filesystem located at /mnt/data?",
      "options": [
        "umount /mnt/data",
        "unmount /mnt/data",
        "detach /mnt/data",
        "mount -d /mnt/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The umount command is used to unmount filesystems in Linux. There is no unmount or detach command for this purpose in standard Linux distributions.",
      "examTip": "Always ensure no process is using the mount point before unmounting."
    },
    {
      "id": 8,
      "question": "Which command allows you to view the available disk space usage on all mounted filesystems in a human-readable format?",
      "options": [
        "df -h",
        "du -h",
        "lsblk",
        "mount"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The df -h command shows disk usage in a human-readable format (-h). du -h shows directory space usage, and lsblk lists block devices.",
      "examTip": "df for disk usage, du for directory usage. Add -h for human-readable output."
    },
    {
      "id": 9,
      "question": "Which configuration file is responsible for defining static hostname settings in a system using systemd?",
      "options": [
        "/etc/hostname",
        "/etc/hosts",
        "/etc/sysconfig/network",
        "/etc/resolv.conf"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The /etc/hostname file defines the static hostname in systems using systemd. /etc/hosts maps hostnames to IP addresses, while /etc/resolv.conf configures DNS.",
      "examTip": "For static hostnames, edit /etc/hostname and use hostnamectl to apply changes."
    },
    {
      "id": 10,
      "question": "You need to schedule a one-time task to run at 3:00 PM tomorrow. Which command would you use?",
      "options": [
        "cron",
        "crontab -e",
        "at 15:00 tomorrow",
        "systemctl schedule"
      ],
      "correctAnswerIndex": 2,
      "explanation": "The at command schedules one-time tasks. cron and crontab are for recurring tasks, and there is no systemctl schedule command.",
      "examTip": "Use at for one-time tasks and cron for recurring tasks."
    },
    {
      "id": 11,
      "question": "Which file contains user account information, including the username, UID, GID, home directory, and default shell?",
      "options": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/profile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The /etc/passwd file stores essential information about user accounts, including usernames, UIDs, GIDs, home directories, and default shells.",
      "examTip": "Remember: /etc/passwd for user info, /etc/shadow for passwords."
    },
    {
      "id": 12,
      "question": "What is the purpose of the 'chmod 755 file.sh' command?",
      "options": [
        "Sets read, write, and execute permissions for the owner, and read and execute for others.",
        "Sets read and write permissions for the owner and execute for others.",
        "Sets execute permissions for all users and read/write for the owner.",
        "Sets full permissions for the owner and no permissions for others."
      ],
      "correctAnswerIndex": 0,
      "explanation": "The chmod 755 command sets permissions where the owner can read, write, and execute, while the group and others can read and execute.",
      "examTip": "Understand octal permissions: 7=read+write+execute, 5=read+execute."
    },
    {
      "id": 13,
      "question": "Which command is used to view the current running kernel version?",
      "options": [
        "uname -r",
        "lsb_release -a",
        "cat /proc/version",
        "dmesg | grep kernel"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The uname -r command displays the current running kernel version directly.",
      "examTip": "Use uname -r frequently to check the kernel after updates."
    },
    {
      "id": 14,
      "question": "Which of the following commands will display all active network interfaces and their IP addresses on a modern Linux system?",
      "options": [
        "ifconfig -a",
        "ip addr show",
        "netstat -i",
        "nmcli dev status"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The ip addr show command is the recommended modern method for listing all active network interfaces and their IP addresses.",
      "examTip": "ip tools have replaced ifconfig in most modern distributions."
    },
    {
      "id": 15,
      "question": "You need to check DNS resolution issues. Which command would BEST help you query DNS records?",
      "options": [
        "ping",
        "dig",
        "netstat",
        "traceroute"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The dig command queries DNS servers and displays detailed responses, making it the best tool for DNS resolution troubleshooting.",
      "examTip": "Use dig for DNS queries; nslookup is older and less feature-rich."
    },
    {
      "id": 16,
      "question": "Which utility would you use to schedule a recurring task that runs every Sunday at 2 AM?",
      "options": [
        "cron",
        "at",
        "systemctl timer",
        "nohup"
      ],
      "correctAnswerIndex": 0,
      "explanation": "cron is used for scheduling recurring tasks, including running jobs at specified times like every Sunday at 2 AM.",
      "examTip": "Remember cron format: minute hour day month weekday command."
    },
    {
      "id": 17,
      "question": "Which runlevel in traditional SysVinit systems corresponds to multi-user mode with networking but without a graphical interface?",
      "options": [
        "3",
        "5",
        "1",
        "0"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Runlevel 3 corresponds to multi-user mode with networking, commonly used for server environments without a GUI.",
      "examTip": "Runlevel 5 includes GUI; Runlevel 3 is CLI with networking."
    },
    {
      "id": 18,
      "question": "Which file contains configuration details for static DNS resolution on Linux systems?",
      "options": [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/network/interfaces",
        "/etc/sysconfig/network"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The /etc/resolv.conf file specifies DNS server information for name resolution.",
      "examTip": "For host-to-IP mappings, check /etc/hosts; for DNS, check /etc/resolv.conf."
    },
    {
      "id": 19,
      "question": "Which systemctl command would you use to permanently enable a service to start on boot?",
      "options": [
        "systemctl start servicename",
        "systemctl enable servicename",
        "systemctl restart servicename",
        "systemctl reload servicename"
      ],
      "correctAnswerIndex": 1,
      "explanation": "The systemctl enable command creates the necessary symlinks so that a service starts automatically on boot.",
      "examTip": "Enable for boot persistence, start for immediate execution."
    },
    {
      "id": 20,
      "question": "Which command shows real-time system resource usage, including CPU, memory, and running processes?",
      "options": [
        "ps aux",
        "htop",
        "vmstat",
        "lsof"
      ],
      "correctAnswerIndex": 1,
      "explanation": "htop provides an interactive, real-time view of system resources, including CPU, memory, and running processes.",
      "examTip": "htop is more user-friendly than top, offering interactive controls."
    },
    {
      "id": 21,
      "question": "Which command will display the total amount of free and used physical memory in the system in a human-readable format?",
      "options": [
        "free -h",
        "top",
        "vmstat",
        "htop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The free -h command displays the total amount of free and used physical and swap memory in a human-readable format.",
      "examTip": "Add -h to free for human-readable output (e.g., MB, GB)."
    },
    {
      "id": 22,
      "question": "Which tool would BEST be used to capture and analyze network packets in real time on a Linux system?",
      "options": [
        "tcpdump",
        "netstat",
        "traceroute",
        "ping"
      ],
      "correctAnswerIndex": 0,
      "explanation": "tcpdump captures network packets in real-time for analysis. It’s ideal for network troubleshooting and security auditing.",
      "examTip": "Use tcpdump for packet-level analysis; Wireshark for GUI-based packet inspection."
    },
    {
      "id": 23,
      "question": "Which of the following commands is used to display or set the system's hostname in a Linux system running systemd?",
      "options": [
        "hostnamectl",
        "hostname -f",
        "sethostname",
        "sysctl -n kernel.hostname"
      ],
      "correctAnswerIndex": 0,
      "explanation": "hostnamectl is the systemd-based command to display or set the system's hostname persistently.",
      "examTip": "hostnamectl is preferred on modern systems using systemd for permanent hostname configuration."
    },
    {
      "id": 24,
      "question": "Which file would you edit to define user environment variables that should be applied when any user logs in system-wide?",
      "options": [
        "/etc/profile",
        "~/.bashrc",
        "/etc/bash.bashrc",
        "~/.bash_profile"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/profile is the system-wide configuration file for setting environment variables applied to all user sessions.",
      "examTip": "System-wide variables? Use /etc/profile. User-specific? Use ~/.bash_profile or ~/.bashrc."
    },
    {
      "id": 25,
      "question": "Which command will find all files named 'config.json' starting from the root directory?",
      "options": [
        "find / -name 'config.json'",
        "locate config.json",
        "grep config.json /",
        "search / config.json"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The find command with -name searches for files matching a specific name recursively from the given directory.",
      "examTip": "find is powerful for real-time searches; locate is faster but relies on an updated database."
    },
    {
      "id": 26,
      "question": "Which command would BEST display the dependencies of a given installed package on a Debian-based system?",
      "options": [
        "apt-cache depends <package>",
        "dpkg -l <package>",
        "apt show <package>",
        "dpkg -s <package>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The apt-cache depends command shows a package's dependencies in Debian-based systems.",
      "examTip": "Use apt-cache depends for dependency information; apt show for general package details."
    },
    {
      "id": 27,
      "question": "Which command would you use to reload the configuration of a running Nginx service without stopping it?",
      "options": [
        "systemctl reload nginx",
        "systemctl restart nginx",
        "nginx -s stop",
        "service nginx stop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "systemctl reload nginx reloads the service's configuration without stopping it, avoiding downtime.",
      "examTip": "Reload = no downtime; Restart = temporary downtime. Use reload for minor config updates."
    },
    {
      "id": 28,
      "question": "Which of the following commands will display the UUID of all mounted filesystems?",
      "options": [
        "blkid",
        "lsblk -f",
        "df -T",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "blkid displays block device attributes, including UUIDs. lsblk -f also shows filesystem info but not always UUIDs.",
      "examTip": "blkid is the go-to for UUIDs; lsblk -f for a broader filesystem overview."
    },
    {
      "id": 29,
      "question": "Which utility is used for compiling source code into binary programs in Linux?",
      "options": [
        "make",
        "gcc",
        "ld",
        "tar"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The make utility reads Makefiles to build programs by compiling and linking code. gcc compiles individual source files.",
      "examTip": "make handles builds using Makefiles; gcc compiles C source code files directly."
    },
    {
      "id": 30,
      "question": "Which system log file typically stores authentication-related messages, including SSH logins and sudo attempts?",
      "options": [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/var/log/auth.log stores authentication-related events, such as SSH logins and sudo command usage on Debian-based systems.",
      "examTip": "Debian systems use /var/log/auth.log; Red Hat systems typically use /var/log/secure."
    },
    {
      "id": 31,
      "question": "Which command would you use to display the last 50 lines of a log file and continue to display new lines as they are appended in real time?",
      "options": [
        "tail -n 50 -f /var/log/syslog",
        "head -n 50 /var/log/syslog",
        "less +50 /var/log/syslog",
        "cat /var/log/syslog | tail -n 50"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The tail -n 50 -f command displays the last 50 lines of a file and continues to show new lines as they are appended, which is useful for real-time log monitoring.",
      "examTip": "Use tail -f for real-time log monitoring during troubleshooting."
    },
    {
      "id": 32,
      "question": "Which file should be edited to change the default runlevel on a system using SysVinit?",
      "options": [
        "/etc/inittab",
        "/etc/init.d/rc",
        "/etc/systemd/system/default.target",
        "/etc/default/grub"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/inittab is used in SysVinit systems to set the default runlevel by modifying the initdefault line.",
      "examTip": "SysVinit uses /etc/inittab; systemd uses default.target for runlevel equivalents."
    },
    {
      "id": 33,
      "question": "Which of the following commands will show the kernel ring buffer messages, typically used for debugging hardware issues?",
      "options": [
        "dmesg",
        "journalctl -k",
        "cat /var/log/dmesg",
        "sysctl -a"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The dmesg command displays the kernel ring buffer messages, which are useful for diagnosing hardware issues during system boot.",
      "examTip": "For persistent kernel logs on systemd systems, use journalctl -k."
    },
    {
      "id": 34,
      "question": "Which type of RAID provides both redundancy and performance by combining disk mirroring and striping?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 3,
      "explanation": "RAID 10 combines RAID 1 (mirroring) and RAID 0 (striping), providing both redundancy and performance improvements.",
      "examTip": "RAID 10 = RAID 1 + RAID 0 (mirroring + striping). Best for high-performance fault-tolerant setups."
    },
    {
      "id": 35,
      "question": "Which command will create a compressed archive named backup.tar.gz of the /home directory?",
      "options": [
        "tar -czvf backup.tar.gz /home",
        "tar -xzvf backup.tar.gz /home",
        "gzip -c /home > backup.tar.gz",
        "zip -r backup.tar.gz /home"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The tar -czvf command creates a compressed (gzip) archive file. -c creates, -z compresses with gzip, -v is verbose, and -f specifies the filename.",
      "examTip": "Remember tar options: -c (create), -z (gzip), -v (verbose), -f (file)."
    },
    {
      "id": 36,
      "question": "Which command shows a list of open files and the processes that opened them?",
      "options": [
        "lsof",
        "ps aux",
        "top",
        "htop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The lsof command lists open files along with the processes that have opened them, which is useful for diagnosing file locking issues.",
      "examTip": "lsof is crucial for identifying which process is using a file or port."
    },
    {
      "id": 37,
      "question": "What is the primary function of the /proc directory in Linux?",
      "options": [
        "Contains configuration files for installed packages.",
        "Holds kernel and process information in a virtual filesystem.",
        "Stores log files related to system operations.",
        "Serves as the default directory for temporary files."
      ],
      "correctAnswerIndex": 1,
      "explanation": "/proc is a virtual filesystem that provides information about running processes and the kernel, often used for system diagnostics.",
      "examTip": "Think of /proc as a window into the kernel and running processes."
    },
    {
      "id": 38,
      "question": "Which of the following commands will display the number of lines, words, and characters in a file named document.txt?",
      "options": [
        "wc document.txt",
        "cat document.txt | wc -l",
        "grep -c '' document.txt",
        "sed -n '$=' document.txt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The wc (word count) command without any options displays the number of lines, words, and characters in a file.",
      "examTip": "wc shows lines (-l), words (-w), and characters (-c)."
    },
    {
      "id": 39,
      "question": "Which file should be modified to make an environment variable available to all users upon login on a systemd-based system?",
      "options": [
        "/etc/environment",
        "~/.bash_profile",
        "/etc/profile.d/custom.sh",
        "/etc/bashrc"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/environment is used for defining system-wide environment variables that apply to all users upon login.",
      "examTip": "For global environment variables, prefer /etc/environment; for scripts, use /etc/profile.d/."
    },
    {
      "id": 40,
      "question": "Which partition type is required when using GUID Partition Table (GPT) for UEFI boot?",
      "options": [
        "EFI System Partition (ESP)",
        "Linux Swap",
        "BIOS Boot Partition",
        "Boot Loader Partition"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The EFI System Partition (ESP) is required for UEFI boot on GPT-partitioned disks. It typically uses the FAT32 filesystem.",
      "examTip": "For UEFI systems with GPT, ensure an ESP partition formatted as FAT32 is present."
    },
    {
      "id": 41,
      "question": "Which of the following commands will modify the default kernel parameters at runtime without rebooting?",
      "options": [
        "sysctl -w",
        "modprobe",
        "lsmod",
        "insmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "sysctl -w modifies kernel parameters at runtime. Changes can be made persistent by adding them to /etc/sysctl.conf.",
      "examTip": "Use sysctl -w for temporary changes; /etc/sysctl.conf for persistent changes."
    },
    {
      "id": 42,
      "question": "Which RAID level provides fault tolerance and parity, allowing for data recovery if a single disk fails?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 10"
      ],
      "correctAnswerIndex": 2,
      "explanation": "RAID 5 uses block-level striping with distributed parity, providing fault tolerance with efficient storage utilization.",
      "examTip": "RAID 5 balances storage efficiency and fault tolerance; requires at least 3 disks."
    },
    {
      "id": 43,
      "question": "Which command would you use to list all active listening ports and their associated processes?",
      "options": [
        "ss -tuln",
        "netstat -anp",
        "lsof -i",
        "ip addr show"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The ss -tuln command displays all listening TCP/UDP sockets in numeric form, replacing netstat in modern distributions.",
      "examTip": "ss is faster and more informative than netstat for socket statistics."
    },
    {
      "id": 44,
      "question": "Which file controls the default permissions assigned to newly created files?",
      "options": [
        "/etc/login.defs",
        "~/.bashrc",
        "/etc/profile",
        "umask"
      ],
      "correctAnswerIndex": 3,
      "explanation": "The umask value determines the default permission set for new files and directories by subtracting its value from the system's default permissions.",
      "examTip": "Default umask is usually 022, resulting in 755 for directories and 644 for files."
    },
    {
      "id": 45,
      "question": "Which command can be used to create a new Logical Volume (LV) named 'data' with a size of 10GB in the volume group 'vg01'?",
      "options": [
        "lvcreate -L 10G -n data vg01",
        "vgcreate vg01 data 10G",
        "pvcreate /dev/sdb1",
        "mkfs.ext4 /dev/vg01/data"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The lvcreate command is used to create logical volumes within a specified volume group.",
      "examTip": "LVM commands: pvcreate (physical), vgcreate (volume group), lvcreate (logical volume)."
    },
    {
      "id": 46,
      "question": "Which tool is BEST used for automating the deployment of configuration changes across multiple Linux servers?",
      "options": [
        "Ansible",
        "Docker",
        "Git",
        "Vagrant"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Ansible is a configuration management tool that automates the deployment of configuration changes across multiple systems.",
      "examTip": "Ansible uses YAML playbooks and requires no agent installation on remote nodes."
    },
    {
      "id": 47,
      "question": "Which command would you use to permanently add a new software repository in a Debian-based system?",
      "options": [
        "echo 'deb http://repo-url/ stable main' >> /etc/apt/sources.list",
        "yum-config-manager --add-repo http://repo-url/",
        "dnf install repository",
        "zypper addrepo http://repo-url/"
      ],
      "correctAnswerIndex": 0,
      "explanation": "In Debian-based systems, software repositories are defined in /etc/apt/sources.list or within /etc/apt/sources.list.d/.",
      "examTip": "Always run apt update after adding a new repository."
    },
    {
      "id": 48,
      "question": "Which command would you use to clone a Git repository from a remote server?",
      "options": [
        "git clone https://github.com/user/repo.git",
        "git pull origin main",
        "git init",
        "git fetch"
      ],
      "correctAnswerIndex": 0,
      "explanation": "git clone is used to copy a remote repository to the local system, including all its history and files.",
      "examTip": "Use git pull to update an existing repository; git clone for initial download."
    },
    {
      "id": 49,
      "question": "Which option BEST describes a container's role in modern Linux environments?",
      "options": [
        "A virtual machine that runs its own kernel and operating system.",
        "An isolated process running on a shared kernel, providing application portability.",
        "A dedicated server running a single application for high performance.",
        "A cloud-based service that automates software deployment."
      ],
      "correctAnswerIndex": 1,
      "explanation": "Containers are isolated processes running on a shared kernel, providing lightweight, portable environments for applications.",
      "examTip": "Containers = lightweight, fast, share host kernel. VMs = heavier, separate kernels."
    },
    {
      "id": 50,
      "question": "Which command will show detailed CPU information, including architecture and model name?",
      "options": [
        "lscpu",
        "cat /proc/cpuinfo",
        "dmidecode -t processor",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "lscpu provides a summary of the CPU architecture, while cat /proc/cpuinfo gives detailed per-core information.",
      "examTip": "lscpu for summarized CPU info; /proc/cpuinfo for detailed, per-core data."
    },
    {
      "id": 51,
      "question": "Which file contains user password hashes in a modern Linux system?",
      "options": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/login.defs"
      ],
      "correctAnswerIndex": 1,
      "explanation": "/etc/shadow contains encrypted user passwords and related account expiration information, providing enhanced security.",
      "examTip": "Ensure /etc/shadow has restricted permissions (typically 600) for security."
    },
    {
      "id": 52,
      "question": "Which Linux command allows secure copying of files between local and remote systems using SSH?",
      "options": [
        "scp",
        "rsync",
        "ftp",
        "sftp"
      ],
      "correctAnswerIndex": 0,
      "explanation": "scp uses SSH for secure file transfer between hosts. Unlike ftp, scp encrypts the data in transit.",
      "examTip": "For more advanced syncing options, use rsync with SSH (-e ssh)."
    },
    {
      "id": 53,
      "question": "Which command displays the routing table on a modern Linux system?",
      "options": [
        "ip route show",
        "netstat -r",
        "route -n",
        "traceroute"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ip route show is the recommended modern command for displaying the kernel's IP routing table, replacing netstat and route.",
      "examTip": "ip route show is part of the iproute2 suite, replacing deprecated net-tools commands."
    },
    {
      "id": 54,
      "question": "Which command will recursively change the ownership of all files and directories under /var/www to user 'webadmin'?",
      "options": [
        "chown -R webadmin /var/www",
        "chmod -R 755 /var/www",
        "usermod -R webadmin /var/www",
        "groupadd webadmin /var/www"
      ],
      "correctAnswerIndex": 0,
      "explanation": "chown -R changes ownership recursively for all files and directories under the specified path.",
      "examTip": "Use chown -R carefully, especially on sensitive system directories."
    },
    {
      "id": 55,
      "question": "Which file should be modified to configure user password aging policies in Linux?",
      "options": [
        "/etc/login.defs",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/default/useradd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/login.defs defines system-wide settings for user account policies, including password aging.",
      "examTip": "Use chage for user-specific password aging settings; /etc/login.defs for global defaults."
    },
    {
      "id": 56,
      "question": "Which command will create a compressed archive using the xz compression algorithm?",
      "options": [
        "tar -cJvf archive.tar.xz /folder",
        "tar -czvf archive.tar.xz /folder",
        "gzip archive.tar",
        "bzip2 archive.tar"
      ],
      "correctAnswerIndex": 0,
      "explanation": "tar -cJvf uses the -J option for xz compression, creating a .tar.xz file.",
      "examTip": "Remember: -z for gzip, -j for bzip2, -J for xz compression with tar."
    },
    {
      "id": 57,
      "question": "Which logical volume management command lists all existing physical volumes?",
      "options": [
        "pvs",
        "vgs",
        "lvs",
        "pvcreate"
      ],
      "correctAnswerIndex": 0,
      "explanation": "pvs lists all physical volumes in the system, showing details like volume group association and size.",
      "examTip": "pvs (physical), vgs (volume groups), lvs (logical volumes) for LVM management."
    },
    {
      "id": 58,
      "question": "Which of the following services synchronizes the system clock with remote NTP servers?",
      "options": [
        "chronyd",
        "sshd",
        "httpd",
        "ntpd"
      ],
      "correctAnswerIndex": 0,
      "explanation": "chronyd is a newer, faster NTP client and server daemon, preferred over ntpd for time synchronization on modern systems.",
      "examTip": "chronyd is more robust for time synchronization on systems that are not always connected to the network."
    },
    {
      "id": 59,
      "question": "Which process state in Linux indicates a process is waiting for I/O operations to complete?",
      "options": [
        "Running",
        "Sleeping",
        "Stopped",
        "Zombie"
      ],
      "correctAnswerIndex": 1,
      "explanation": "Sleeping processes are those that are waiting for an event such as I/O completion before continuing execution.",
      "examTip": "Use ps aux or top to check process states when troubleshooting performance issues."
    },
    {
      "id": 60,
      "question": "Which command will display all users currently logged into the system?",
      "options": [
        "w",
        "whoami",
        "id",
        "groups"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The w command shows who is logged in and what they are doing, including idle time and system load averages.",
      "examTip": "who shows logged-in users only; w shows more detailed session information."
    },
    {
      "id": 61,
      "question": "Which utility would BEST help analyze why a system service failed to start at boot on a systemd-based Linux system?",
      "options": [
        "journalctl -xe",
        "systemctl list-units",
        "dmesg",
        "ps aux"
      ],
      "correctAnswerIndex": 0,
      "explanation": "journalctl -xe shows detailed logs, including those related to service failures, making it ideal for troubleshooting systemd issues.",
      "examTip": "Use journalctl -u servicename for logs specific to a particular service."
    },
    {
      "id": 62,
      "question": "Which command creates a new user account with a specified home directory?",
      "options": [
        "useradd -m username",
        "adduser -d /home/username username",
        "usermod -d /home/username username",
        "passwd username"
      ],
      "correctAnswerIndex": 0,
      "explanation": "useradd -m creates a new user and automatically generates a home directory at /home/username.",
      "examTip": "useradd -m for new users with home directories; passwd username to set user passwords."
    },
    {
      "id": 63,
      "question": "Which SSH configuration file allows specifying host-specific settings for all users on the system?",
      "options": [
        "/etc/ssh/ssh_config",
        "/etc/ssh/sshd_config",
        "~/.ssh/config",
        "/etc/hosts.allow"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/ssh/ssh_config is the client configuration file for SSH and applies system-wide to all users for outgoing SSH connections.",
      "examTip": "sshd_config controls server-side SSH settings; ssh_config is for the client side."
    },
    {
      "id": 64,
      "question": "Which type of RAID provides redundancy by mirroring data across multiple disks but without striping?",
      "options": [
        "RAID 0",
        "RAID 1",
        "RAID 5",
        "RAID 6"
      ],
      "correctAnswerIndex": 1,
      "explanation": "RAID 1 provides redundancy by mirroring data across multiple disks, offering fault tolerance if one disk fails.",
      "examTip": "RAID 1 = Mirroring; suitable for systems requiring high data availability."
    },
    {
      "id": 65,
      "question": "Which tool is used to define policies for SELinux on Red Hat-based systems?",
      "options": [
        "semanage",
        "getenforce",
        "chcon",
        "setsebool"
      ],
      "correctAnswerIndex": 0,
      "explanation": "semanage is used to configure SELinux policy settings, such as port contexts and file contexts.",
      "examTip": "Use getenforce to check SELinux status; semanage for policy configuration."
    },
    {
      "id": 66,
      "question": "Which system call mechanism allows regular users to execute commands with superuser privileges after authentication?",
      "options": [
        "sudo",
        "su -",
        "pkexec",
        "chmod +s"
      ],
      "correctAnswerIndex": 0,
      "explanation": "sudo allows permitted users to execute commands as the superuser or another user, as specified in /etc/sudoers.",
      "examTip": "Always use visudo to edit /etc/sudoers to avoid syntax errors."
    },
    {
      "id": 67,
      "question": "Which command would BEST help you identify all listening network ports and associated services on a Linux server?",
      "options": [
        "ss -lntp",
        "netstat -plnt",
        "lsof -i -P -n",
        "nmap localhost"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ss -lntp lists all listening ports (-l), shows numeric addresses (-n), TCP (-t), and associated processes (-p).",
      "examTip": "ss is faster than netstat and preferred on modern systems."
    },
    {
      "id": 68,
      "question": "Which file specifies repositories for YUM on Red Hat-based systems?",
      "options": [
        "/etc/yum.repos.d/*.repo",
        "/etc/yum.conf",
        "/etc/dnf/dnf.conf",
        "/etc/apt/sources.list"
      ],
      "correctAnswerIndex": 0,
      "explanation": "YUM repository definitions are typically stored in .repo files within the /etc/yum.repos.d/ directory.",
      "examTip": "YUM for Red Hat-based systems; APT for Debian-based systems."
    },
    {
      "id": 69,
      "question": "Which of the following commands displays the amount of disk space used by each directory in the /home directory, in human-readable format?",
      "options": [
        "du -h /home/*",
        "df -h /home",
        "ls -lh /home",
        "lsblk /home"
      ],
      "correctAnswerIndex": 0,
      "explanation": "du -h /home/* displays the disk usage of each directory under /home in a human-readable format (e.g., MB, GB).",
      "examTip": "df shows filesystem space; du shows directory/file usage."
    },
    {
      "id": 70,
      "question": "Which utility would you use to create a new partition on a storage device in a modern Linux environment?",
      "options": [
        "parted",
        "fdisk",
        "mkfs",
        "lsblk"
      ],
      "correctAnswerIndex": 0,
      "explanation": "parted is a modern partitioning tool that supports both MBR and GPT partition tables, suitable for disks larger than 2TB.",
      "examTip": "Use parted for GPT and large disks; fdisk for MBR on smaller disks."
    },
    {
      "id": 71,
      "question": "Which command will display the SELinux security context for files in the /var/www directory?",
      "options": [
        "ls -Z /var/www",
        "getsebool -a",
        "semanage fcontext -l",
        "restorecon -R /var/www"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The ls -Z command shows the SELinux security context for files, which is useful for verifying proper labeling in directories like /var/www.",
      "examTip": "Use ls -Z for quick SELinux context checks; semanage for detailed policy management."
    },
    {
      "id": 72,
      "question": "Which command will show the system's current runlevel on a SysVinit-based system?",
      "options": [
        "runlevel",
        "systemctl get-default",
        "init 3",
        "who -r"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The runlevel command displays the previous and current runlevel, which is crucial for understanding the system's operational state.",
      "examTip": "For systemd systems, use systemctl get-default instead of runlevel."
    },
    {
      "id": 73,
      "question": "Which tool would you use to permanently configure a static IP address on a system using NetworkManager?",
      "options": [
        "nmcli",
        "ifconfig",
        "ip addr add",
        "netplan apply"
      ],
      "correctAnswerIndex": 0,
      "explanation": "nmcli is the command-line interface for NetworkManager, allowing permanent configuration of networking settings, including static IP addresses.",
      "examTip": "Use nmcli for dynamic and persistent network configurations on modern Linux distributions."
    },
    {
      "id": 74,
      "question": "Which command will display all kernel modules currently loaded on a system?",
      "options": [
        "lsmod",
        "modinfo",
        "modprobe -l",
        "insmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "lsmod lists all currently loaded kernel modules, showing their dependencies and usage counts.",
      "examTip": "lsmod shows loaded modules; modprobe adds/removes modules; modinfo shows module details."
    },
    {
      "id": 75,
      "question": "Which filesystem type is known for supporting snapshots and dynamic inode allocation in Linux?",
      "options": [
        "Btrfs",
        "Ext4",
        "XFS",
        "FAT32"
      ],
      "correctAnswerIndex": 0,
      "explanation": "Btrfs supports advanced features like snapshots, dynamic inode allocation, and built-in RAID capabilities, making it ideal for modern workloads.",
      "examTip": "Btrfs = snapshots + scalability; Ext4 = general-purpose with broad compatibility."
    },
    {
      "id": 76,
      "question": "Which command will display a hierarchical tree of running processes on the system?",
      "options": [
        "pstree",
        "ps aux",
        "top",
        "htop"
      ],
      "correctAnswerIndex": 0,
      "explanation": "pstree displays running processes in a tree format, showing parent-child relationships between processes.",
      "examTip": "pstree for visualizing process hierarchies; ps aux for detailed process lists."
    },
    {
      "id": 77,
      "question": "Which utility would BEST help identify disk I/O bottlenecks by reporting CPU and disk statistics in real time?",
      "options": [
        "iostat",
        "vmstat",
        "top",
        "lsof"
      ],
      "correctAnswerIndex": 0,
      "explanation": "iostat reports CPU and disk I/O statistics, helping identify bottlenecks related to storage performance.",
      "examTip": "Combine iostat with vmstat for comprehensive system performance analysis."
    },
    {
      "id": 78,
      "question": "Which of the following commands is used to safely extend an existing logical volume by 5GB?",
      "options": [
        "lvextend -L +5G /dev/vg01/lv_data",
        "lvcreate -L 5G /dev/vg01/lv_data",
        "resize2fs /dev/vg01/lv_data +5G",
        "vgextend vg01 /dev/sdb1"
      ],
      "correctAnswerIndex": 0,
      "explanation": "lvextend -L +5G extends the size of an existing logical volume by 5GB. After extending, resize2fs may be used for filesystem resizing.",
      "examTip": "Always resize the filesystem after extending a logical volume with resize2fs or xfs_growfs, depending on the filesystem type."
    },
    {
      "id": 79,
      "question": "Which directory typically contains device files representing hardware devices in a Linux system?",
      "options": [
        "/dev",
        "/proc",
        "/sys",
        "/lib"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/dev contains device files that represent hardware components and peripherals, enabling user-space processes to interact with hardware.",
      "examTip": "Block devices (e.g., /dev/sda) and character devices (e.g., /dev/tty) reside in /dev."
    },
    {
      "id": 80,
      "question": "Which utility would BEST display a list of open network connections, listening ports, and associated processes on a system?",
      "options": [
        "ss -tunap",
        "netstat -anp",
        "nmap localhost",
        "tcpdump"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ss -tunap displays TCP/UDP sockets with associated processes and listening ports, replacing netstat on modern Linux systems.",
      "examTip": "ss is faster than netstat; use ss -tunap for comprehensive network diagnostics."
    },
    {
      "id": 81,
      "question": "Which command will search for the string 'error' in all .log files under /var/log, showing line numbers for matches?",
      "options": [
        "grep -n 'error' /var/log/*.log",
        "find /var/log -name '*.log' | grep 'error'",
        "awk '/error/ {print $0}' /var/log/*.log",
        "sed -n '/error/p' /var/log/*.log"
      ],
      "correctAnswerIndex": 0,
      "explanation": "grep -n shows matching lines along with line numbers, making it ideal for log file analysis when searching for specific strings like 'error'.",
      "examTip": "Add -r to grep for recursive searches across directories."
    },
    {
      "id": 82,
      "question": "Which command would you use to forcefully terminate a process with PID 1234?",
      "options": [
        "kill -9 1234",
        "kill -15 1234",
        "pkill 1234",
        "killall 1234"
      ],
      "correctAnswerIndex": 0,
      "explanation": "kill -9 sends the SIGKILL signal, which forcefully terminates the process without allowing cleanup.",
      "examTip": "Try kill -15 (SIGTERM) first for graceful termination before using kill -9."
    },
    {
      "id": 83,
      "question": "Which file should be edited to configure the default shell for all new user accounts on a Linux system?",
      "options": [
        "/etc/default/useradd",
        "/etc/passwd",
        "/etc/shells",
        "/etc/login.defs"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/default/useradd defines default values for new user accounts, including the default shell.",
      "examTip": "To change the default shell system-wide, modify /etc/default/useradd and ensure the shell is listed in /etc/shells."
    },
    {
      "id": 84,
      "question": "Which command displays the system's uptime along with the number of logged-in users and load averages?",
      "options": [
        "uptime",
        "w",
        "top",
        "vmstat"
      ],
      "correctAnswerIndex": 0,
      "explanation": "uptime shows how long the system has been running, how many users are currently logged on, and the system load averages for the past 1, 5, and 15 minutes.",
      "examTip": "Load averages help indicate CPU demand; values higher than the number of cores suggest CPU bottlenecks."
    },
    {
      "id": 85,
      "question": "Which command will schedule a job to run only once at 4:00 PM tomorrow?",
      "options": [
        "echo '/path/to/script.sh' | at 16:00 tomorrow",
        "crontab -e",
        "systemctl schedule script.sh 16:00 tomorrow",
        "nohup /path/to/script.sh &"
      ],
      "correctAnswerIndex": 0,
      "explanation": "The at command schedules one-time tasks. The example uses echo to specify the script to run at 4:00 PM tomorrow.",
      "examTip": "For recurring jobs, use cron; for one-time jobs, use at."
    },
    {
      "id": 86,
      "question": "Which file specifies PAM (Pluggable Authentication Module) rules for user login authentication?",
      "options": [
        "/etc/pam.d/login",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/ssh/sshd_config"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/pam.d/login defines PAM rules for login authentication, specifying which modules handle user verification.",
      "examTip": "PAM configurations in /etc/pam.d/ control authentication for various system services."
    },
    {
      "id": 87,
      "question": "Which command creates a hard link named hardlink.txt pointing to file.txt?",
      "options": [
        "ln file.txt hardlink.txt",
        "ln -s file.txt hardlink.txt",
        "cp file.txt hardlink.txt",
        "link file.txt hardlink.txt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ln without the -s option creates a hard link, which points directly to the file's inode, unlike symbolic links that reference the file path.",
      "examTip": "Hard links share inodes; symbolic links reference file paths and break if the target is deleted."
    },
    {
      "id": 88,
      "question": "Which command will display disk I/O statistics, including read and write rates for each device?",
      "options": [
        "iostat",
        "vmstat",
        "iotop",
        "df -h"
      ],
      "correctAnswerIndex": 0,
      "explanation": "iostat provides CPU and I/O statistics for devices and partitions, helping identify disk-related performance issues.",
      "examTip": "Use iostat for disk performance; iotop for real-time I/O usage by processes."
    },
    {
      "id": 89,
      "question": "Which file must exist and be properly configured for a system to boot using GRUB2 on BIOS systems?",
      "options": [
        "/boot/grub2/grub.cfg",
        "/etc/default/grub",
        "/boot/grub/menu.lst",
        "/boot/efi/EFI/grub.cfg"
      ],
      "correctAnswerIndex": 0,
      "explanation": "/boot/grub2/grub.cfg contains GRUB2's boot menu configuration on BIOS systems. It is typically generated using grub2-mkconfig.",
      "examTip": "Regenerate grub.cfg using grub2-mkconfig if boot menu issues occur."
    },
    {
      "id": 90,
      "question": "Which command provides detailed information about a specific kernel module, including its parameters and dependencies?",
      "options": [
        "modinfo modulename",
        "lsmod | grep modulename",
        "modprobe -l modulename",
        "insmod modulename"
      ],
      "correctAnswerIndex": 0,
      "explanation": "modinfo displays detailed information about a specified kernel module, including description, license, dependencies, and parameters.",
      "examTip": "Use modinfo before loading modules to understand their purpose and requirements."
    },
    {
      "id": 91,
      "question": "Which command will display all currently loaded kernel modules along with their dependencies and memory usage?",
      "options": [
        "lsmod",
        "modinfo",
        "modprobe -l",
        "insmod"
      ],
      "correctAnswerIndex": 0,
      "explanation": "lsmod lists all currently loaded kernel modules, including their dependencies and memory usage.",
      "examTip": "lsmod provides a quick overview of active kernel modules; use modinfo for detailed information about a specific module."
    },
    {
      "id": 92,
      "question": "Which of the following BEST describes the purpose of the /etc/fstab file?",
      "options": [
        "It defines static information about filesystems for automatic mounting during boot.",
        "It contains information about user accounts and default shells.",
        "It stores configuration settings for network interfaces.",
        "It manages dynamic mount points for removable media."
      ],
      "correctAnswerIndex": 0,
      "explanation": "/etc/fstab specifies filesystems and mount options that should be automatically mounted at boot time.",
      "examTip": "Always back up /etc/fstab before making changes to avoid boot issues."
    },
    {
      "id": 93,
      "question": "Which command will show the available space and usage of all mounted filesystems in a human-readable format?",
      "options": [
        "df -h",
        "du -sh /*",
        "lsblk",
        "mount"
      ],
      "correctAnswerIndex": 0,
      "explanation": "df -h displays available disk space and usage for all mounted filesystems in a human-readable format (e.g., MB, GB).",
      "examTip": "Remember: df for filesystem usage, du for directory usage."
    },
    {
      "id": 94,
      "question": "Which command is used to display detailed CPU architecture information, including cores and threads per CPU?",
      "options": [
        "lscpu",
        "cat /proc/cpuinfo",
        "dmidecode -t processor",
        "top"
      ],
      "correctAnswerIndex": 0,
      "explanation": "lscpu provides a concise summary of CPU architecture, including the number of cores, threads, and other essential CPU details.",
      "examTip": "lscpu is faster for summaries; /proc/cpuinfo shows detailed per-core data."
    },
    {
      "id": 95,
      "question": "Which service is responsible for resolving DNS queries on systems using systemd-resolved?",
      "options": [
        "systemd-resolved",
        "named",
        "dnsmasq",
        "bind9"
      ],
      "correctAnswerIndex": 0,
      "explanation": "systemd-resolved handles DNS resolution on systems using systemd, providing network name resolution for local applications.",
      "examTip": "Check DNS resolution status using systemctl status systemd-resolved or resolvectl status."
    },
    {
      "id": 96,
      "question": "Which of the following commands would display the UUID of all block devices on a Linux system?",
      "options": [
        "blkid",
        "lsblk -f",
        "fdisk -l",
        "mount -l"
      ],
      "correctAnswerIndex": 0,
      "explanation": "blkid displays the UUIDs of all block devices, which is essential when configuring persistent mounts in /etc/fstab.",
      "examTip": "Use blkid when configuring persistent mounts using UUIDs for reliability."
    },
    {
      "id": 97,
      "question": "Which tool would you use to create a persistent firewall rule allowing SSH access using firewalld?",
      "options": [
        "firewall-cmd --permanent --add-service=ssh",
        "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
        "ufw allow ssh",
        "nft add rule inet filter input tcp dport 22 accept"
      ],
      "correctAnswerIndex": 0,
      "explanation": "firewall-cmd --permanent --add-service=ssh adds a persistent rule for SSH access when using firewalld.",
      "examTip": "Always reload firewalld after adding permanent rules with firewall-cmd --reload."
    },
    {
      "id": 98,
      "question": "Which process management command sends the SIGHUP signal to a running process to reinitialize its configuration without stopping it?",
      "options": [
        "kill -HUP <PID>",
        "kill -9 <PID>",
        "pkill -HUP <process_name>",
        "killall -15 <process_name>"
      ],
      "correctAnswerIndex": 0,
      "explanation": "kill -HUP sends the SIGHUP signal, which many daemons interpret as a command to reload their configuration files.",
      "examTip": "SIGHUP (Hang Up) is commonly used for reloading configurations without downtime."
    },
    {
      "id": 99,
      "question": "Which command will display all scheduled cron jobs for the current user?",
      "options": [
        "crontab -l",
        "crontab -e",
        "cron -l",
        "systemctl list-timers"
      ],
      "correctAnswerIndex": 0,
      "explanation": "crontab -l lists all cron jobs scheduled for the current user, showing timing and associated commands.",
      "examTip": "crontab -e edits cron jobs; crontab -l lists them."
    },
    {
      "id": 100,
      "question": "Which Linux command is used to create a symbolic link named link.txt pointing to file.txt?",
      "options": [
        "ln -s file.txt link.txt",
        "ln file.txt link.txt",
        "cp file.txt link.txt",
        "link file.txt link.txt"
      ],
      "correctAnswerIndex": 0,
      "explanation": "ln -s creates a symbolic (soft) link pointing to the target file, which remains valid even if the link is moved, as long as the relative path remains accessible.",
      "examTip": "Symbolic links reference file paths, while hard links reference inodes directly."
    }
  ]
});
