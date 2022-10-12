This is a simple simulator tool that helps you sniff network packets and display them in your command line.
The tool is mainly built on top of python scapy module ( here you can be more familiar with it => https://scapy.net) 


Quick disclaimer that if you are using older version of python scapy. Plese use (from scapy.all import * ) instead of  (from scapy import *)
To kill all process just press   Ctrl+C ... 

PLEASE RUN AS ROOT!!!
 
$ sudo python sniff.py -i wlan0      
$ sudo python sniff.py -v -i wlan0  => (or  lo , tun0 , tun1 , eth0)
