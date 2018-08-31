#! /usr/bin/env python

import sys
import json
from math import log1p
import urllib2
import os
import gmplot
from scapy.all import *
import url_info
import geoip2.database #geoip for detecting ip origin



class analysis:
 def __init__(self, time_first_packet):
  self.freq = 0
  self.country = " "
  self.isp = " "
  self.backscatter_IP = []
  self.protocols = {}
  self.time = []
  self.ip_src = []
  self.start = time_first_packet
  self.end = time_first_packet
  self.variation_time = 0
  self.packets_second = 0

 def addFreq(self):
  self.freq +=1

 def addBackscatter(self,ip):
  self.backscatter_IP.append(ip)


 def addTime(self,time_s ):
  #Get the time of each packet
  self.time.append(time_s)

 def addProtocol(self, protocol):
  if protocol in self.protocols:
   self.protocols[protocol] += 1
  else:
   self.protocols[protocol] = 1

 def addIPsrc(self, src):
  self.ip_src.append(src)

 def setEnd(self,last_time):
  self.end = last_time
  self.variation_time = self.end - self.start
  if(self.variation_time>1):
   self.packets_second = len(self.time)/self.variation_time
  else:
   self.packets_second = 0


#prompt = "Please, tell me the directory where the packets are, your highness: "

#Storing the packet into a variable
print (os.getcwd())
freq_IP = dict()
text = os.path.join(os.getcwd(),"prueba")
print("El directorio donde busco es: ", text)
source_IPs = {}
db_path = os.path.join(os.getcwd(),"geoDB\\GeoLite2-City.mmdb")
reader = geoip2.database.Reader(db_path)

db_path_asn = os.path.join(os.getcwd(),"geoDB\\GeoLite2-ASN.mmdb")
reader_asn = geoip2.database.Reader(db_path_asn)

for file in os.listdir(text):
 file_name = os.path.join(text,file)
 print("Leyendo archivo: ", file_name)
 #Storing the packet into a variable
 packets = rdpcap(file_name)
 #Iterate through the packets
 #Create dictionary to store IP freq

 for packet in packets:

  if(packet.haslayer(IP)):
    ip = str(packet[IP].dst)
    ip_src = str(packet[IP].src)
    if ip in freq_IP:
     if(ip_src in source_IPs):
      source_IPs[ip_src]+=1
     else:
      source_IPs[ip_src] =1

     if(packet.haslayer(ICMP) and packet[ICMP].type == 11):
      freq_IP[ip].addFreq()
      freq_IP[ip].addTime(packet.time)
      freq_IP[ip].setEnd(packet.time)
      freq_IP[ip].addIPsrc(ip_src)
      freq_IP[ip].addProtocol('ICMP')

      freq_IP[ip].addBackscatter(ip)
     elif(packet.haslayer(UDP)):
      freq_IP[ip].addProtocol('UDP')
      freq_IP[ip].addFreq()
      freq_IP[ip].addTime(packet.time)
      freq_IP[ip].setEnd(packet.time)
      freq_IP[ip].addIPsrc(ip_src)
      freq_IP[ip].addBackscatter(ip_src)
     elif(packet.haslayer(TCP)):
      if(packet[TCP].flags == 'SA' or packet[TCP].flags == 'RA' or packet[TCP].flags == 'R' or packet[TCP].flags == 'A' ):
       freq_IP[ip].addProtocol('TCP')
       freq_IP[ip].addFreq()
       freq_IP[ip].addTime(packet.time)
       freq_IP[ip].setEnd(packet.time)
       freq_IP[ip].addIPsrc(ip_src)
       freq_IP[ip].addBackscatter(ip)

    else:
     if(ip_src in source_IPs):
      source_IPs[ip_src]+=1
     else:
      source_IPs[ip_src] =1
     freq_IP[ip]  = analysis(packet.time)



     if(packet.haslayer(ICMP) and packet[ICMP].type == 11):
      freq_IP[ip].addProtocol('ICMP')
      freq_IP[ip].addFreq()
      freq_IP[ip].addTime(packet.time)
      freq_IP[ip].addIPsrc(ip_src)

     elif(packet.haslayer(UDP)):
      freq_IP[ip].addProtocol('UDP')
      freq_IP[ip].addFreq()
      freq_IP[ip].addTime(packet.time)
      freq_IP[ip].addIPsrc(ip_src)

     elif(packet.haslayer(TCP)):
      if(packet[TCP].flags == 'SA' or packet[TCP].flags == 'RA' or packet[TCP].flags == 'R' or packet[TCP].flags == 'A' ):
       freq_IP[ip].addProtocol('TCP')
       freq_IP[ip].addFreq()
       freq_IP[ip].addTime(packet.time)
       freq_IP[ip].addIPsrc(ip_src)

for x in freq_IP:
 if(x in source_IPs):
  print("SOURCE IP DETECTED")
 else:
  if(freq_IP[x].packets_second >0):
   #TODO Check differentiation between backscatter and requests.
   for y in freq_IP[x].protocols:
    if(int(freq_IP[x].protocols[y])>100):
     response = reader.city(x)
     response_asn = reader_asn.asn(x)
     if(y == 'UDP'): #Check if packet protocol is UDP
      if(x in source_IPs):
         frequency = math.log1p((source_IPs[x]+1)/(freq_IP[x].freq+1)) #Check packet simmetry (https://www.utwente.nl/en/eemcs/dacs/assignments/completed/master/reports/2008-sande.pdf)
         if(frequency>1): #Checking the simmetry is not 0, thus, malicious flow
          print x, " : ",   freq_IP[x].protocols, "Packets backscattered: ", freq_IP[x].freq,"\n","Variation: ", freq_IP[x].variation_time,"\n", "Packets_second: ", freq_IP[x].packets_second,"\n", "City name:" , url_info.urlgetCity(x),"\n", "Country name:" , url_info.urlgetCountry(x) ,"\n" ,"ISP", response_asn.autonomous_system_organization
      else:
          print x, " : ",   freq_IP[x].protocols, "Packets backscattered:: ", freq_IP[x].freq,"\n","Variation: ", freq_IP[x].variation_time,"\n", "Packets_second: ", freq_IP[x].packets_second,"\n", "City name:" , url_info.urlgetCity(x),"\n", "Country name:" , url_info.urlgetCountry(x) ,"\n" ,"ISP", response_asn.autonomous_system_organization
     else:
      print x, " : ",   freq_IP[x].protocols, "Packets backscattered:: ", freq_IP[x].freq,"\n","Variation: ", freq_IP[x].variation_time,"\n", "Packets_second: ", freq_IP[x].packets_second,"\n", "City name:" , url_info.urlgetCity(x),"\n", "Country name:" , url_info.urlgetCountry(x) ,"\n" ,"ISP", response_asn.autonomous_system_organization
