db.tests.insertOne({
  "category": "linuxplus",
  "testId": 7,
  "testName": "Linux+ Practice Test #7 (Challenging)",
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
    }
 
