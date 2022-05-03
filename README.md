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