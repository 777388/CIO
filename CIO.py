import json
import socket
import subprocess
import requests
from multiprocessing import Pool
from shodan import Shodan
import sys
# specify the Shodan API key
api_key = "[cookie]"

# create a Shodan client
shodan_client = Shodan(api_key)

# function to get the domain from an IP
def get_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

# function to get the software and version running on a domain
def get_software_and_version(domain):
    try:
        result = subprocess.run(["whatweb", domain], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "HTTP Server" in line:
                software, version = line.split(":")[1].strip().split(" ")
                return domain, software, version
    except Exception as e:
        print(e)
        return None, None, None
# function to check if a domain is behind Cloudflare
def check_cloudflare(domain):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0'}
        response = requests.get(f'https://{domain}', headers=headers)
        if 'cloudflare' in response.headers.get('server', '').lower():
            print(f'{domain} is behind Cloudflare')
        else:
            print(f'{domain} is not behind Cloudflare')
    except Exception as e:
        print(f'An error occurred while checking {domain} for Cloudflare: {e}')
    
# function to check for hop-by-hop headers and see if it opens a connection to backend servers
def check_hopbyhop(domain):
    try:
        headers = {'Connection': 'close'}
        response = requests.get(domain, headers=headers)
        if 'Connection' in response.headers:
            if response.headers['Connection'] == 'close':
                print(f'{domain} does not open a connection to backend servers')
            else:
                print(f'{domain} opens a connection to backend servers')
        else:
            print(f'{domain} opens a connection to backend servers')
    except Exception as e:
        print(f'An error occurred while checking {domain} for hop-by-hop headers: {e}')

# function to get the corresponding CVEs for a software and version
def get_cves(software, version):
    try:
        url = f"https://cve-search.org/api/cvefor/{software}/{version}"
        response = requests.get(url)
        data = json.loads(response.text)
        return data["data"]
    except Exception as e:
        print(e)
        return []
# function to scan for HTTP request smuggling vulnerabilities
def check_http_request_smuggling(domain):
    try:
        headers = {'Transfer-Encoding': 'chunked'}
        payload = '0\r\n\r\n'
        response = requests.post(f'https://{domain}', headers=headers, data=payload)
        if response.status_code == 400:
            print(f'HTTP request smuggling vulnerability not found on {domain}')
        else:
            print(f'HTTP request smuggling vulnerability found on {domain}')
    except Exception as e:
        print(f'An error occurred while checking {domain} for HTTP request smuggling vulnerabilities: {e}')

# function to check for H2C smuggling in each request to domains and subdomains
def check_h2c_smuggling(domain):
    try:
        headers = {'Connection': 'Upgrade', 'Upgrade': 'h2c'}
        response = requests.get(f'https://{domain}', headers=headers, allow_redirects=False)
        if response.status_code == 101:
            print(f'H2C Smuggling is possible on {domain}')
        else:
            print(f'H2C Smuggling is not possible on {domain}')
    except Exception as e:
        print(f'An error occurred while checking {domain} for H2C smuggling: {e}')

# function to check for web cache poisoning vulnerability
def check_web_cache_poisoning(domain):
    try:
        headers = {'Cache-Control': 'max-age=0'}
        r1 = requests.get(f'https://{domain}', headers=headers)
        headers = {'Cache-Control': 'max-age=0', 'X-Poison': 'poison'}
        r2 = requests.get(f'https://{domain}', headers=headers)
        if r1.content == r2.content:
            print(f'Web cache poisoning vulnerability not found on {domain}')
        else:
            print(f'Web cache poisoning vulnerability found on {domain}')
    except Exception as e:
        print(f'An error occurred while checking {domain} for web cache poisoning vulnerability: {e}')
# function to check for server-side inclusion (SSI) or edge-side inclusion (ESI) vulnerabilities
def check_ssi_or_esi(domain):
    try:
        response = requests.get(f'https://{domain}?include=http://example.com/file')
        if response.status_code == 200 and 'example.com' in response.text:
            print(f'Server-side inclusion (SSI) or Edge-side inclusion (ESI) vulnerability found on {domain}')
        else:
            print(f'Server-side inclusion (SSI) or Edge-side inclusion (ESI) vulnerability not found on {domain}')
    except Exception as e:
        print(f'An error occurred while checking {domain} for server-side inclusion (SSI) or edge-side inclusion (ESI) vulnerabilities: {e}')
# search Shodan for the specified query
results = shodan_client.search(sys.argv[1])


# create a pool of worker processes
with Pool() as p:
    # use the map function to get the domains from the IPs
    domains = list(filter(None, p.map(get_domain, [result["ip_str"] for result in results["matches"]])))
# create a pool of worker processes
with Pool() as p:
    # use the map function to get the software and version running on the domains
    software_and_versions = p.map(get_software_and_version, domains)
# create a pool of worker processes
with Pool() as p:
    # use the map function to get the corresponding CVEs for the software and versions
    cves = p.map(get_cves, [(x[1],x[2]) for x in software_and_versions])
# create a pool of worker processes
with Pool() as p:
    # use the map function to check if the domains are behind Cloudflare
    p.map(check_cloudflare, domains)
# create a pool of worker processes
with Pool() as p:
    # use the map function to check for H2C smuggling in each request to domains and subdomains
    p.map(check_h2c_smuggling, domains)
# create a pool of worker processes
with Pool() as p:
    # use the map function to check for web cache poisoning vulnerability
    p.map(check_web_cache_poisoning, domains)
# create a pool of worker processes
with Pool() as p:
    # use the map function to scan for HTTP request smuggling vulnerabilities
     p.map(check_http_request_smuggling, domains)
# create a pool of worker processes
with Pool() as p:
    # use the map function to check for server-side inclusion (SSI) or edge-side inclusion
    p.map(check_ssi_or_esi, domains)
    
# flatten the list of cves and print the domain name with the each cve
for domain,cves in zip([x[0] for x in software_and_versions],cves):
    for cve in cves:
        print(f"{domain} - {cve['id']}")
