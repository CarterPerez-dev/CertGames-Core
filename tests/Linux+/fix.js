  
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



#7
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
  
  
