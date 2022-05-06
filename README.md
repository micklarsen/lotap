# My list of tools and programs 

> A List of tools and programs with examples on how to use them.  
> Compiled for studies at Københavns Erhvervsakademi (KEA) in Bachelor of IT-Security

# Wireshark
**A Network protocol analyzer.**
TBD

# tcpdump
**A full packet capture tool.**  
Basically what Wireshark does, but does it on the commandline in linux.  

## Examples
Capture traffic on device NIC and write to dump.pcap:  
`tcpdump -i eth0 -w dump.pcap`  

Dump a packet with verbose output:  
`sudo tcpdump -vv tcp port 80 and dst host dr.dk`  

Create a new pcap file with filters applied:  
`sudo tcpdump -r testfile.pcap -w testfile2.pcap 'tcp port 80'`

# capinfos  
Display meta-data about a capture file  

## Examples

Display metadata about capture:  
`capinfos testfile.pcap`

# editcap  
Can make large pcap files more managable by splitting them up into smaller files.  

## Examples

Split a pcap file into smaller files of 1000 packets each:  
`editcap -c 1000 cap.pcapng cap1000`   

Split based on dates:  
`editcap -B "2017-09-03 18:26:51" cap.pcapng cap2.pcapng`

# tshark  
Just as powerful as wireshark, but more scaleable. Better for repetetive jobs.  

## Examples  

Read a file:  
`tshark -r f5-honeypot-release.pcap | head`  

Apply wireshark filters using -Y option:  
`tshark -r f5-honeypot-release.pcap -Y 'tcp.flags.ack==1 && tcp.flags.syn==1' | head` 

Look for DNS:  
`tshark -r cap.pcapng -Y 'dns.qry.name==demo.testfire.net'`

# Netflow
Collects metadata from packets - is **not** full packet capture.  
Consists of three main components:  
- Exporter: `fprobe` that generates netflow updates
- Collector: `nfcapd` accepts updates from the exporter
- Analysis: `nfdump` tool to query netflow data

# Nmap
Network scanner 

## Examples
OS Fingerprint scan:  
`nmap -O -v 192.168.55.128`  

Scan a network for hosts:  
`nmap -vv -n -sn -T4 192.168.186.1/24` 

Scan a specific target:  
`sudo nmap -vv -Pn -sS -A 192.168.186.129`

# Scapy
Packet sniffer and injector.  
Can be used to craft custom packets

## Examples
Usage:  
- send()	Sends a packet in layer 3
- sendp() 	Sends a packet in layer 2
- sr()		Send and wait for response
- sniff()	sniffs traffic
- rdpcap() 	import a pcap file

Craft a package, send and show reply:  
1. `pkt=IP(src='192.168.186.128',dst='192.168.186.131')/ICMP(type=8)`  
2. `ans = sr1(pkt)`  
3. `ans.show()`

Sniff traffic:  
1. `pkts = sniff(count=5,filter=“tcp")`
2. `pkts.summary()`
3. `pkts[1].show()`

Import a pcap:  
`pkts  = rdpcap(‘capture.pcap')`

Create a SYN flood  
`packet = IP(src="192.168.65.131",dst="192.168.65.1")/TCP(dport=80,flags="S")`
`srflood(packet)`

Create ARP poisin  

*We create a ARP packet with a fake MAC (hwsrc) and fake IP (psrc).*
*We disguise the packet as a who-has, and force the attacked device (pdst) to reply. Thereby it stores the entry in its ARP table*  

`packet = Ether()/ARP(op="who-has",hwsrc="00:0c:29:2a:f9:7b",psrc="192.168.117.2",pdst="192.168.117.131")`  
`sendp(packet)`  

We can achieve something similar with is-at:  

`packet = Ether()/ARP(op="is-at",hwdst="ff:ff:ff:ff:ff:ff",hwsrc="00:0c:29:2a:f9:7b",psrc="192.168.117.2",pdst=" 192.168.117.131")`  
`sendp(packet)`

And of course we will have to send a similar ARP to the router.

# BURP Suite
Web application traffic suite.  
Can intercept traffic and replace/inject traffic and much more.  

# SOF-ELK  
**Security operations and forensics | Elastisearch, Logstash, Kibana**  
A "Big" data analytics platform.  
Logs are sent and stored in SOF-ELK and can be analyzed and much more.  
Detection, logging and threat hunting.

# Security Onion (IDS/IPS)  
A big collection of tools:  
- NIDS/NIPS
    - Suricata
- Analysis tool
    - Security Onion Console (SOC)
    - Kibana
- Logging
    - Zeek
    - Stenographer
    - HIDS
    - Wazuh
- Other tools
    - Grafana	
    - CyberChef
    - Strelka

# Nagios (SNMP)
Web interface for SNMP monitoring.  
Can be configured with rules and will provide monitoring and alerts