import os
import time


def check_files():
    if os.path.isfile("known_exploited_vulnerabilities.json"):
        print("vulnerability list found...")
        st_time=time.time()
        if (st_time - os.path.getmtime("known_exploited_vulnerabilities.json")) > 604800:
            print("Vulnerability list older than 7 days... refreshing")
            os.system("wget -O https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        
    else:
        print("vulnerability list not found.... downloading.....")
        os.system("wget https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        print("Download complete")
        
    if os.path.isfile("ports.json"):
        print("Ports list found....")
    else:
        print("Ports list not found.... Downloading....")
        os.system("wget https://raw.githubusercontent.com/djcas9/ports.json/refs/heads/master/ports.json")
