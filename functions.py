import requests
import time
import sys
import nmap #PATH
import whois #PATH
import dns.resolver
from socket import *

nscan = nmap.PortScanner()

class CreateConnection(socket):
	def __init__(self):
		super().__init__(AF_INET, SOCK_STREAM) #TPC/IP
		self.client = super()

	def _bind(self):
		return super().bind()

	def _listen(self):
		return super().listen(10)

	def __str__(self):
		return "Joining the Network at: %s" %(time.strftime("%a-%d-%m-%Y / %H:%M"))

	def _ip(self, site):
		return gethostbyname(site)

	def _inputS(self):
		return sys.argv[1]

	def _list(self):
		return ["admin", "robots.txt", "login", "dashboard", "dash"] # Lista Personalizada 

	def _listD(self):
		return ["admin", "www", "dashboard", "login", "dash"]

	def _choice(self):
		return "Choose module:\n[1] - BruteForce\n[2] - PortScan\n[3] - Nmap\n"	

class ExecuteAll(CreateConnection):
	def __init__(self):
		super().__init__()
		self.client = CreateConnection()

	def BruteForce(self):
		for st in self.client._list():
			if(requests.get("https://" + "%s/%s" %(self.client._inputS(), st)).status_code == 200):
				print("[~] Open: %s" %(st))
			
	def PortScan(self):
		for port in [80, 79, 443, 5000, 8000]:
			if(self.client.connect_ex(("%s" %(str(self.client._inputS())), int(port))) == 0):
				print("[~] Open: %s" %(port))

	def DnsBrute(self):
		for sub in self.client._listD():
			try:
				for result in dns.resolver.query("%s.%s" %(sub, self.client._inputS()), "a"):
					print("[%s] - %s" %(sub, result))
			except:
				pass

	def Nmap(self):
		nscan.scan(self.client._inputS(), ports="1-1024", arguments="-v -sS")
		for host in nscan.all_hosts():
			print("-"*20 + "\n" + "Host: %s (%s)\nState: %s" %(host, nscan[host].hostname(), nscan[host].state()))
			for p in nscan[host].all_protocols():
				print("Protocol: %s\n" %(p) + "-"*20)
				for port in nscan[host][p].keys():	
					print("Port: %s\nState: %s\n" %(port, nscan[host][p][port]['state']))

	def WhoIs(self):
		return whois.query(self.client._inputS()).__dict__

a = ExecuteAll()
print(a.WhoIs())



