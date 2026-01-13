## Encrypted C2 Beacon Response

### Triage Steps
1. **Network Analysis**

   ```kql
   # Elasticsearch query
   event.category:network AND destination.port:443 
   AND packet.length > 128 AND network.ttl IN (64, 128, 255)
   