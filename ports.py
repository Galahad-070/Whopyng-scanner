import json
from fuzzywuzzy import fuzz
import ipaddress

port_file=open('ports.json','r')
port_data=json.load(port_file)
port_list=port_data["ports"]

vuln_file=open("known_exploited_vulnerabilities.json",'r')
vuln_data=json.load(vuln_file)
vuln_list=vuln_data["vulnerabilities"]


def check_port(port):
    for i in port:
        try:
            if i in port_list:
                print('Port',i)
                print("Description of port:",port_list[i]["description"])
                print("Status:",port_list[i]["status"])
                print("TCP:",port_list[i]["tcp"])
                print("UDP:",port_list[i]["udp"])
                print("\n")
                return port_list[i]["description"]
            else:
                print(f'port data of {i} not found')
        except:
            print("Error: Couldn't find the description")

    

def search_vulnerabilities( keyword, threshold=70, max_results=5):
    results = []
    for vuln in vuln_list:
        combined_text = " ".join([
            vuln.get("vendorProject", ""),
            vuln.get("product", ""),
            vuln.get("vulnerabilityName", ""),
            vuln.get("shortDescription", "")
        ])

        
        score = fuzz.partial_ratio(keyword, combined_text.lower())

        if score >= threshold:
            results.append((score, vuln))

        if len(results) >= max_results:
            break

    results.sort(reverse=True, key=lambda x: x[0])
    return results


import ipaddress

def generate_ip_range(ip_prefix):
    try:
        network = ipaddress.IPv4Network(ip_prefix, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        return False

