# Cyber Notes
Structured cybersecurity notes, and references

Cyber Notes

Overview
This repository contains structured cybersecurity notes focused on networking fundamentals, ports and protocols, detection concepts, and tool references. The goal is to build strong foundational knowledge and practical Blue Team thinking.

Current Focus
- Ports and Protocols
- Networking Fundamentals
- Log Analysis Basics
- Vulnerability Assesment Concenpts

Structure 
  Networking
  - Contains notes on core networking concepts such as OSI model, TCP vs UDP, port ranges, and common services.

  Ports and Protocols
  - Documents common ports, associated services, transport protocols, common attacks, and detection ideas.

  Blue Team Concepts
  - Covers common attack patterns, log sources, and detection strategies.

  Tools
  - Notes and references for tools such as nmap, Wireshark, Nessus, and log analysis utilities.


Goals
- Build fast recall of common ports and services
- Connect services to real world attack scenarios
- Practice detection thinking
- Document learning progress over time

**Ports and Protocols**
Port 20
Service: FTP Data
Transport: TCP
Function: Transfers FTP data channel
Common Attack: Unencrypted data exposure
Detection Clue: Plaintext file transfer traffic observed

Port 21
Service: FTP
Transport: TCP
Function: File transfer
Common Attack: Credential exposure
Detection Clue: FTP login attempts in network logs

Port 22
Service: SSH
Transport: TCP
Function: Secure remote login
Common Attack: Brute force attempts
Detection Clue: Multiple failed authentication attempts

Port 23
Service: Telnet
Transport: TCP
Function: Remote login
Common Attack: Credential sniffing
Detection Clue: Cleartext login attempts

Port 25
Service: SMTP
Transport: TCP
Function: Sends email
Common Attack: Spam relay abuse
Detection Clue: High outbound email traffic
