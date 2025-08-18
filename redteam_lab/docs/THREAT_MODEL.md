## STRIDE Analysis for C2 Simulation

| Threat        | Mitigation                          | Implementation |
|---------------|-------------------------------------|----------------|
| Spoofing      | Packet encryption                   | AES-256-GCM    |
| Tampering     | HMAC verification                   | (TODO)         |
| Repudiation   | Detailed logging                    | CloudWatch Logs|
| Info Disclosure | Memory-safe languages              | Python/Rust    |
| DoS           | Rate limiting                       | iptables rules |
| Elevation     | Non-root execution                  | IAM roles      |

## Attack Tree
```mermaid
graph TD
    A[Establish C2] --> B[Encrypted Channel]
    A --> C[Persistence]
    B --> D[Beaconing]
    C --> E[Cron Jobs]