#!/bin/bash
ip=$1

nmap -sV "$ip"
nmap -sV --script vuln "$ip"
