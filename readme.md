
# Usage
need sudo to use port 53
With one terminal:
```bash
sudo bash -c 'python3 dns.py > /dev/null 2>&1' & dig rm-fr.ca @127.0.0.1
sudo fuser -k 53/udp
```
Can currently only retrieve A records, other domains don't work since this is an authoritative dns server which
Needs a zone file per domain it has authority over.

## Todo
Add support for more types of records.
Create script to automatically create zone files by parsing output of dig.
