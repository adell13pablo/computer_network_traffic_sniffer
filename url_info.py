
import sys
import json
import urllib2
import os

 
def urlgetCity(ip):
 url = urllib2.urlopen('http://api.db-ip.com/v2/eddfa6b24de19f41da84a43c2c9f70015f422822/'+ip)
 response = url.read()
 data = json.loads(response)
 return (data['city'])
 
def urlgetCountry(ip):
  url = urllib2.urlopen('http://api.db-ip.com/v2/eddfa6b24de19f41da84a43c2c9f70015f422822/'+ip)
  response = url.read()
  data = json.loads(response)
  return (data['countryName'])