#!/bin/bash
# Generated automatically by PySpark Analyzer

echo 'Blocking malicious attacker IP: 192.168.1.10'
sudo iptables -A INPUT -s 192.168.1.10 -j DROP
echo 'Blocking malicious attacker IP: 172.16.0.22'
sudo iptables -A INPUT -s 172.16.0.22 -j DROP
echo 'Blocking malicious attacker IP: 10.0.0.5'
sudo iptables -A INPUT -s 10.0.0.5 -j DROP
echo 'Blocking malicious attacker IP: 198.51.100.12'
sudo iptables -A INPUT -s 198.51.100.12 -j DROP
echo 'Blocking malicious attacker IP: 203.0.113.5'
sudo iptables -A INPUT -s 203.0.113.5 -j DROP
echo 'Blocking malicious attacker IP: 192.168.1.50'
sudo iptables -A INPUT -s 192.168.1.50 -j DROP
