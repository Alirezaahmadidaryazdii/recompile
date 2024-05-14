import requests
from bs4 import BeautifulSoup
import dns.resolver
import requests
import socket
import re
import nmap
import whois
from urllib.parse import urlparse
import argparse
# from tenacity import retry, stop_after_attempt, wait_fixed
#!#################################function in step 1#############################################

def get_AllLinks(url, depth, links_list):
    if depth == 0:
        return
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            links_list.append(link['href'])
            get_AllLinks(link['href'], depth-1, links_list)
    except Exception as e:
        print(e)

#!#################################function in step 2#############################################

def get_All_subdomain(domain):

    # todo name the domain is :

    lines = []
    listsSuccessData = []
    # todo  get line by line in file txt and save in lines array 
    with open('subdomain/wordlist.txt', 'r') as file:
        for line in file:
            lines.append(line.strip())

    #* Resolve NS records for the domain
    resolver = dns.resolver.Resolver()
    ns = resolver.resolve(domain, 'NS')
    for subdomain in lines:
        try: #? if contact sudomain in domain is successfull is save in array listsSuccessData
            #* Perform a DNS lookup for the subdomain
            answers = resolver.resolve(subdomain + "." + domain, "A")
            for ip in answers:
                print(subdomain + "." + domain + " - " + str(ip))
                listsSuccessData.append(subdomain+"."+domain);
        except: #! if contact subdomain in domain not successfull is pass
            pass 
    return listsSuccessData    

#!#################################function in step 3#############################################

def get_ip_Addres(domain):
    #? get Ip in domain
    ip_address = socket.gethostbyname(domain)

    print(f"The IP address of {domain} is {ip_address}")
    dataIp = ip_address
    return dataIp

#!#################################function in step 4#############################################

def get_port_open(ip):
    successIp = [] #todo the variable is save the Ip is open
    #* List of commonly used ports to scan
    common_ports = [21, 22, 23, 25, 53, 80, 110, 119, 123, 143, 161, 194, 443, 445, 993, 995]

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  #? Set timeout to 1 second
        result = sock.connect_ex((ip, port))
        if result == 0:
            print("Port {} is open".format(port))
            successIp.append(port)
        else:
            print("Port {} is closed".format(port))
        sock.close()
    return successIp   

#!#################################function in step 5#############################################
def check_status_server(url):
    try:
        response = requests.get(url)
        response.ra.ise_for_status()  #todo Check if the request was successful
        return "Success!"  #* If successful, print "Success!"\
    except requests.HTTPError as errh:
        return "Http Error:"+errh  #! If HTTP error occurs, print the error message
    except requests.ConnectionError as errc:
        return "Error Connecting:"+ errc  #? If a connection error occurs, print the error message
    except requests.Timeout as errt:
        return "Timeout Error:"+ errt  #! If a timeout error occurs, print the error message
    except requests.RequestException as err:
        return "Oops, something went wrong:"+ err #// If any other error occurs, print the error message    

#!#################################function in step 6#############################################
# @retry(stop=stop_after_attempt(3), wait=wait_fixed(1))
def extract_numbers_from_html(html_text):
    pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
    numbers = re.findall(pattern, html_text)
    return numbers
def extract_emails_from_html(html_text):
    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    emails = re.findall(pattern, html_text)
    return emails
def extract_contact_info(url_subdomain, list_phones, list_emails):
    try:
        response = requests.get(url_subdomain)
        # response.raise_for_status()  # بررسی وضعیت درخواست
        soup = BeautifulSoup(response.text, 'html.parser')
        html_text = soup.get_text()
        # response = requests.get(url)
        # text = response.text

        # soup = BeautifulSoup(text, 'html.parser')
        list_phones.append(extract_numbers_from_html(html_text))
        list_emails = extract_emails_from_html(html_text)
        return list_phones, list_emails
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None, None 
def extract_contact_info_from_subdomains():
    # Assuming get_All_subdomain returns a list of subdomains
    subdomains = []
    get_AllLinks('https://www.w3schools.com/', 2, subdomains)
    all_emails = []
    all_phones = []

    for subdomain in subdomains:
        # Ensure subdomain has a scheme
        if not subdomain.startswith(('http://', 'https://')):
            subdomain = 'https:/' + subdomain

        extract_contact_info(subdomain, all_phones, all_emails)

    return all_emails, all_phones

# main_url = 'https://www.w3schools.com/'
# emails, phones = extract_contact_info_from_subdomains(main_url)


# emails, phones = extract_contact_info_from_subdomains()
# print(emails, phones)


#!######################################################step 6 is ok##########################
def get_regex(domain):
    subdomains = get_All_subdomain(domain) #
    lists_email = []
    lists_phone = []
    for subdomain in subdomains :
        if subdomain.startswith("http://"):
            subdomain = subdomain.replace("http://", "https://")
        if subdomain.startswith("/"):
            subdomain = subdomain[1:]
            subdomain = 'https://'+subdomain
        lists_email.append(ReP(subdomain))
        lists_phone.append(ReE(subdomain))
    return lists_phone, lists_phone  

def ReP(url):
    url = 'https://'+url
    try:
        response = requests.get(url)
        text = response.text

        soup = BeautifulSoup(text, 'html.parser')
        
        phone_pattern = r"\b(\d{3}[-.]?\d{3}[-.]?\d{4})\b"
        phones = re.findall(phone_pattern, text)

        return phones
    except Exception as e:
        
        print(f"An error occurred: {e}")
        pass

def ReE(url):
    url = 'https://'+url
    try:
        response = requests.get(url)
        text = response.text

        soup = BeautifulSoup(text, 'html.parser')

        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        emails = re.findall(email_pattern, text)

        return emails
    except Exception as e:
        print(f"An error occurred: {e}")
        pass
# phones, emails = get_request('w3schools.com')
# print(phones)
# print(emails)    
#!#################################function in step 7#############################################
def whois_server_url(domain):
    datas_server = []
    w = whois.whois(domain)
    datas_server.append(("Domain registrar:", w.registrar))
    datas_server.append(("WHOIS server:", w.whois_server))
    datas_server.append(("Domain creation date:", w.creation_date))
    datas_server.append(("Domain expiration date:", w.expiration_date))
    datas_server.append(("Domain last updated:", w.last_updated))
    datas_server.append(("Name servers:", w.name_servers))
    datas_server.append(("Registrant name:", w.name))
    datas_server.append(("Registrant organization:", w.org))
    datas_server.append(("Registrant email:", w.email))
    datas_server.append(("Registrant phone:", w.phone))
    return datas_server

#!#################################function in step 8#############################################



def sdjljsd():
    parser = argparse.ArgumentParser(description='Process some inputs.')
    parser.add_argument('--number', type=int, help='process a number')
    parser.add_argument('--text', type=str, help='process some text')
    parser.add_argument('--flag', action='store_true', default=False,
                        help='set a flag')
    parser.add_argument('files', nargs='*', help='process one or more files')

    args = parser.parse_args()

    if args.number is not None:
        print(f"Processing number: {args.number}")
    if args.text is not None:
        print(f"Processing text: {args.text}")
    if args.flag:
        print("Flag is set")
    if args.files:
        print(f"Processing {len(args.files)} file(s): {', '.join(args.files)}")
sdjljsd()
# $ python args-example.py --number 42
# Processing number: 42

# $ python args-example.py --text "Hello, world!"
# Processing text: Hello, world!

# $ python args-example.py --flag
# Flag is set

# $ python args-example.py file1.txt file2.txt
# Processing 2 file(s): file1.txt, file2.txt

# $ python args-example.py --text "Hello" file.txt
# Processing text: Hello
# Processing 1 file(s): file.txt

#!########################################################################3

