
import dns.resolver
import requests
import socket
import re
import nmap
from urllib.parse import urlparse
import whois
#* import function Modul in recompile
from recompile import get_AllLinks as step1
from recompile import get_All_subdomain as step2
from recompile import get_ip_Addres as step3
from recompile import get_port_open as step4
from recompile import check_status_server as step5
from recompile import get_regex as step6
from recompile import whois_server_url as step7
#!###########################################Step 1 ###################################################
#? use the function in modular in recomplie in get_AlLLinks for get all link in website
# url = 'https://example.com'
# depth = 2
# links_list = []
# step1(url, depth, links_list)

#!###########################################Step 2 ###################################################
    #* the code is save the successful subdomain contact in domain and save in a variable and returen

# subdomain = step2("w3schools.com")
# print(subdomain)


#* material########################################################################################
#? Iterate over the name servers and perform a DNS lookup for the subdomain using each nameserver
# for server in ns:
#     server_str = str(server)
#     print("Name Server:", server_str)

#     #* Resolve the IP address of the nameserver domain
#     try:
#         server_ip = socket.gethostbyname(server_str)
#         print("Resolved IP:", server_ip)
#         #* Set the resolved IP address as the nameserver for the resolver
#         resolver.nameservers = [server_ip]       
#     except dns.resolver.NoNameservers:
#         print("No nameservers found for", server_str)
#     except socket.gaierror as e:
#         print("Error resolving IP for", server_str, ":", e)
#*###########################################################################################


#!###########################################Step 3 ###################################################
## * this the code is work in get Ip in domain and return Ip domain

# ip = step3("w3schools.com")


#!############################################Step 4 ###################################################


# dataip = ip  #* Replace with the IP address you want to scan
# ports = step4(dataip)
#!###########################################Step 5 ###################################################



# url = " https://www.w3schools.com"
# step5(url)



#!###########################################Step 6 ###################################################


phones, emails = step6('w3schools.com')


#!###########################################Step 7 ###################################################

# data = step7('w3schools.com')

#!###########################################Step 8 ###################################################