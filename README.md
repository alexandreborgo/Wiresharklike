Wiresharklike
=============

Compilation
-----------

javac *.java


Simple execution
----------------

java Wiresharklike filname


Execution with filters
----------------------

java Wiresharklike filname filter value (...)

example: java Wiresharklike toto.pcap proto http ip.src 192.168.0.1

stacked filters will work as logical OR.

Available filters and values:
-----------------------------

proto : tcp, udp, http, arp, icmp.

mac.addr (src or dst): anything
mac.src: anything
mac.dst: anything

ip.addr (src or dst): anything 
ip.src : anything
ip.dst : anything

port (src or dst): anything
port.src: anything
port.dst: anything

