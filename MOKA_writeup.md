Write-up for MOKA's Machine

Introduction:

Welcome to MOKA’s Cryptic Adventure! This room is designed to test your basic penetration testing skills, focusing on enumeration, exploitation, and privilege escalation. The goal of this challenge is to uncover all flags hidden within the system and escalate from a low-privileged user to root access.

Step 1: Initial Enumeration
The first step in any penetration test is to perform thorough enumeration. Start by scanning for open ports using nmap:

nmap -sC -sV <target_ip>
This will reveal the open ports and the services running on the target machine. You should find FTP and possibly SSH open, both of which are critical for this challenge.

Step 2: Discovering the FTP Username
The FTP service is one of the key points of access. Upon connecting to FTP, you’ll need to find the correct username. The username is hidden in the system's welcome message. After connecting to the FTP server, carefully examine the banner or greeting message that’s displayed, as it contains a clue to the username.

Step 3: Accessing the System
Once you have the correct username, use FTP to login and look for any accessible files that could contain valuable information for further exploitation. Depending on the system configuration, you might find useful files that can help you with privilege escalation.

Step 4: Privilege Escalation
After gaining access, the next critical step is privilege escalation. The user kld is restricted, and we need to escalate privileges to root. In this challenge, you need to look for misconfigured sudo permissions. Check the sudoers file or use the following command to examine the user's permissions:

sudo -l
Look for any command that the kld user can run as root without a password. If found, use it to escalate to root.

Step 5: Finding the Flags
Once you have root access, your next goal is to find the flags. The first flag, user.txt, is located in the user’s home directory. The second flag, root.txt, is located in the root user’s directory.

To find user.txt:

cat /home/kld/user.txt
And for root.txt:

cat /root/root.txt
Conclusion:

This challenge successfully combines multiple penetration testing techniques, including enumeration, exploitation, and privilege escalation. By following the steps outlined in the write-up, you should be able to complete the challenge and capture all flags. This exercise provides a solid foundation for those looking to improve their practical hacking skills.
