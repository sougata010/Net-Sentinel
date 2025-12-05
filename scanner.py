import nmap
import sys
import socket
import json
target_ip = "192.168.0.1/24"
if len(sys.argv) > 1:
    target_ip = sys.argv[1]

def get_hostname(ip, nmap_name):
    if nmap_name and nmap_name != ip: 
        return nmap_name
    try:
        return socket.gethostbyaddr(ip)[0]
    except: 
        return ""
def get_hostname(ip, nmap_name):
    if nmap_name and nmap_name != ip: return nmap_name
    try: return socket.gethostbyaddr(ip)[0]
    except: return ""
def analyze_risk(port, service_name):
    risk = "low"
    info = f"Standard {service_name} service"
    fix = "Ensure service is patched and updated."
    if port == 21:
        risk = "high"
        info = "FTP: Insecure file transfer. Data sent in cleartext."
        fix = "Disable FTP. Use SFTP (Port 22) or FTPS instead."
    elif port == 23:
        risk = "high"
        info = "Telnet: Unencrypted remote access. Passwords visible!"
        fix = "CRITICAL: Disable immediately. Use SSH (Port 22)."
    elif port == 445:
        risk = "high"
        info = "SMB: Windows File Sharing. Vulnerable to Ransomware."
        fix = "Block Port 445 on Firewall. Disable SMBv1 protocol."
    elif port == 3389:
        risk = "high"
        info = "RDP: Windows Remote Desktop exposed to internet."
        fix = "Place behind a VPN or restrict access via Firewall."
    elif port == 5900:
        risk = "high"
        info = "VNC: Remote Desktop. Often has weak passwords."
        fix = "Tunnel VNC through SSH or use a VPN."
    elif port == 80 or port == 8080:
        risk = "medium"
        info = "HTTP: Web traffic is unencrypted."
        fix = "Enforce HTTPS (Port 443) with a valid SSL certificate."
    elif port == 3306:
        risk = "medium"
        info = "MySQL: Database listening on network."
        fix = "Bind to localhost (127.0.0.1) or restrict IP access."
    elif port == 5432:
        risk = "medium"
        info = "PostgreSQL: Database listening on network."
        fix = "Configure pg_hba.conf to restrict remote connections."
    elif port == 25:
        risk = "medium"
        info = "SMTP: Email Relay. Can be used for spam."
        fix = "Disable open relay configuration."
    elif port == 554:
        risk = "medium"
        info = "RTSP: Camera stream. Often has weak/default credentials."
        fix = "Update camera firmware and set a strong password."
    elif port == 5555:
        risk = "medium"
        info = "ADB: Android Debug Bridge exposed."
        fix = "Disable 'Wireless Debugging' on the Android device."
    elif port == 22:
        risk = "low"
        info = "SSH: Secure remote access."
        fix = "Use Key-based authentication and disable root login."
    elif port == 443:
        risk = "low"
        info = "HTTPS: Secure encrypted web traffic."
        fix = "Ensure TLS 1.2/1.3 is enabled."
    elif port == 53:
        risk = "low"
        info = "DNS: Domain Name Service."
        fix = "Ensure recursion is disabled if not public."
    elif port == 631:
        risk = "low"
        info = "IPP: Internet Printing Protocol."
        fix = "Restrict access to local network only."

    return risk, info, fix

ip=target_ip
nm=nmap.PortScanner()
output_list=[]
scanning=nm.scan(hosts=ip,arguments="-F -T4 -sV --version-light --min-hostgroup 64 -Pn -O --osscan-limit")#NORMAL SCAN

for host in nm.all_hosts():
    vuln_list = []
    for proto in nm[host].all_protocols():
        for port in (nm[host][proto].keys()): 
            state = nm[host][proto][port]["state"]

            if state == "open":
                service = nm[host][proto][port]["name"]
                risk_status,info_status,fix_status=analyze_risk(port,service)
                vuln_list.append({
                    "port": port,
                    "service": service,
                    "risk": risk_status,
                    "info": info_status,
                    "remediation": fix_status
                })
        
        hostname = nm[host].hostname()
        resolved_name = get_hostname(host, hostname)
        vendor_name = ""
        if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
            mac_addr = nm[host]['addresses']['mac']
            if 'vendor' in nm[host] and mac_addr in nm[host]['vendor']:
                vendor_name = nm[host]['vendor'][mac_addr]
        os_name = ""
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            os_name = nm[host]['osmatch'][0]['name']
        if resolved_name:
            display_name = resolved_name
        elif vendor_name:
            display_name = f"{vendor_name} Device"
        elif os_name:
            display_name = os_name
        else:
            display_name="Unknown Device"
        
        output_list.append({
        "ip": host,
        "type":display_name,
        "vulns": vuln_list
        })
print(json.dumps(output_list))
