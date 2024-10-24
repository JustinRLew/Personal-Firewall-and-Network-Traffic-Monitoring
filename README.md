# Personal Firewall and Network Monitoring Project

## Overview

This project demonstrates how to configure a personal firewall and set up network monitoring on a Windows system. It highlights the use of Windows Defender Firewall, PowerShell, Wireshark, and Nmap to secure a machine by controlling network traffic, monitoring real-time traffic, and analyzing logs for potential threats.

The purpose of this project is to simulate real-world scenarios where a machine needs to be protected from unauthorized access and malicious activity by configuring precise firewall rules and monitoring network behavior.

---

## Tools Used

- **Windows Defender Firewall**: A built-in firewall on Windows that is used to create and manage inbound and outbound rules.
- **PowerShell**: A command-line shell and scripting language used to automate firewall management.
- **Wireshark**: A network protocol analyzer used for real-time traffic capture and analysis.
- **Nmap**: A network scanning tool used to test firewall effectiveness by simulating network scans and attacks.

---

## Project Setup

### 1. **Environment Setup**

1. **PowerShell**: Ensure the latest version of PowerShell is installed on the Windows machine. Verify the version by running:
   ```powershell
   $PSVersionTable.PSVersion
Nmap: Download and install Nmap from Nmap's official website. After installation, verify it by running:

bash

nmap --version
Wireshark: Download and install Wireshark from Wireshark's website. This tool will be used for real-time network monitoring.

2. Firewall Configuration with Windows Defender Firewall
Block All Incoming Traffic by Default:

Open Windows Defender Firewall > Advanced Settings.
Set the default policy for Inbound Connections to Block.
Allow Essential Services:

Allow Remote Desktop Protocol (RDP) on port 3389 by creating an inbound rule:

Go to Inbound Rules > New Rule > Port.
Choose TCP and specify port 3389.
Set the rule to Allow the connection.
Similarly, create rules for HTTP (port 80) and HTTPS (port 443).

Block Specific IP Addresses:

To block malicious IP addresses, create a custom rule:
Under Inbound Rules, go to New Rule > Custom > Scope.
Specify the IP address to block, such as 203.0.113.5.
Set the action to Block the connection.
Advanced Firewall Settings:

To block a range of IP addresses, specify the range in the Scope section.
Implement rate limiting for SSH connections to prevent brute-force attacks by setting a connection threshold.
3. Firewall Management with PowerShell
Allow RDP Using PowerShell:

powershell

New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
Block Specific IP:

powershell

New-NetFirewallRule -DisplayName "Block IP 203.0.113.5" -Direction Inbound -RemoteAddress 203.0.113.5 -Action Block
Block ICMP (Ping Requests):

powershell

New-NetFirewallRule -DisplayName "Block ICMP" -Protocol ICMPv4 -Direction Inbound -Action Block
View All Active Firewall Rules:

powershell

Get-NetFirewallRule | Format-Table -Property Name, Enabled, Direction, Action
Remove a Firewall Rule:

powershell

Remove-NetFirewallRule -DisplayName "Block IP 203.0.113.5"

4. Network Monitoring Using Wireshark
Capture Live Traffic:

Open Wireshark and select the network interface to capture traffic (e.g., Ethernet or Wi-Fi).
Start capturing traffic and apply filters such as:
wireshark

tcp.port == 80  # To filter HTTP traffic
Monitor Traffic from a Specific IP:

wireshark

ip.src == 203.0.113.5
Detect SYN Flood Attacks:

Apply this filter to detect SYN packets:
wireshark

tcp.flags == 0x02
Testing Firewall with Wireshark:

Ensure that blocked IPs do not appear in the Wireshark captures.
Check allowed traffic (e.g., HTTP) to confirm it passes through the firewall correctly.

5. Firewall Testing Using Nmap
Basic Nmap Scan:

Run an Nmap scan to discover open ports on the machine:
bash
nmap -v -A localhost

Simulate a SYN Scan:
Test how the firewall responds to SYN scans by running:
bash
nmap -sS localhost

Test Blocked IPs:

Simulate traffic from a blocked IP by running:
bash

nmap -v -A <target_ip> -S 203.0.113.5
Review Firewall Logs:

After running the Nmap scan, check the firewall logs at:
plaintext

C:\Windows\System32\LogFiles\Firewall\pfirewall.log
Cross-Check Results with Wireshark:

Confirm that no traffic from blocked IPs appears in the Wireshark capture.

6. Logging and Analyzing Traffic
Enable Firewall Logging:

Go to Windows Defender Firewall > Advanced Settings > Monitoring.
Enable logging for dropped packets and allowed connections.
Logs can be found at:
plaintext

C:\Windows\System32\LogFiles\Firewall\pfirewall.log
Analyze Logs:

Regularly review the logs to detect repeated attempts from specific IPs, which may indicate malicious activity.
Analyze Traffic in Wireshark:

Save captured traffic as a .pcap file for further analysis.
Use filters to detect suspicious activity, such as SYN flooding or unusual amounts of traffic from specific IPs.

Conclusion
This project demonstrates the ability to configure and manage a personal firewall on a Windows system, using both Windows Defender Firewall and PowerShell. By leveraging Wireshark and Nmap, the project also shows how to monitor and analyze network traffic in real-time, identify potential threats, and verify that the firewall is effectively blocking unauthorized traffic.



## License:
This project is licensed under the MIT License.
