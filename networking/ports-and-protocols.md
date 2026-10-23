# Ports and Protocols

These are study notes documenting common network services, their transport protocols, security risks, and possible detection clues.

| Port | Service | Transport | Function | Security concern | Detection clue |
|---|---|---|---|---|---|
| 20 | FTP Data | TCP | Transfers FTP data | Unencrypted data exposure | Plaintext file transfer traffic |
| 21 | FTP | TCP | File transfer | Credential exposure | FTP login attempts in network logs |
| 22 | SSH | TCP | Secure remote login | Brute-force attempts | Multiple failed authentication attempts |
| 23 | Telnet | TCP | Remote login | Credential sniffing | Cleartext login attempts |
| 25 | SMTP | TCP | Sends email | Spam relay abuse | High outbound email traffic |

## Study goals
- Recall common ports and services.
- Connect network services to possible attacks.
- Identify useful clues in network traffic and authentication logs.

> These notes are learning references, not evidence of a completed security investigation.
