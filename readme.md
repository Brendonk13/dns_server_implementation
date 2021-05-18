# Setup
```
git clone https://github.com/Brendonk13/dns_server_implementation
cd dns_server_implementation
```

# Usage
Need sudo to use port 53  
Sleep command needed to avoid the client sending a request before the server has started -- very slow without this command due to this issue.
```bash
sudo bash -c 'python3 dns.py > /dev/null 2>&1' & sleep 1 && dig rm-fr.ca @127.0.0.1
sudo fuser -k 53/udp
```
Can currently only retrieve A records.  
Support for other domains can be implemented by adding zone files to `data/zones` directory

# Todo
- Add support for more types of records.
- Create script to automatically create zone files by parsing output of dig.

# Dns specification
https://www.ietf.org/rfc/rfc1035.txt
