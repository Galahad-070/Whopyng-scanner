import requirements
requirements.check_files()

import multithreading
import ports
import detection


def start_scan(ip_address,type,os_detection,vuln_detection):
    port_description=[]
    up_targets=[]
    all_targ=ports.generate_ip_range(ip_address)

    if all_targ!=False:
        pass
    else:
        print("IP error....exiting")
        exit() 


    up_targets=detection.ping_ips_concurrently(all_targ)
    print("All online Targets-\n")
    for i in up_targets:
        print(i)
    print("\n")
    for target in up_targets:
        print("\n\n","-" * 30,"\n\n")
        print("IP address: ",target,"\n\n")
        if os_detection==True:
            print("Detecting OS\n",detection.detect_device_os(target))
        
        if type=="all":
            tcp_open=multithreading.scan_tcp(target,range(65535))
            udp_open=multithreading.scan_udp(target,range(65535))
        else:
            tcp_open=multithreading.scan_tcp(target)
            udp_open=multithreading.scan_udp(target)
        
        print("TCP open ports- ",tcp_open)
        print("UDP open ports- ",udp_open)


        open_ports=tcp_open+udp_open
        open_ports.sort()
        open_ports_str = list(map(str, open_ports))
        port_description.append(ports.check_port(open_ports_str))


        if vuln_detection==True:
            if udp_open==[] and tcp_open==[]:
                print("Exiting.... no vulnerability to show")

            else:
                print("Checking for vulnerabilities.....\n")
                for i in port_description:
                    results=ports.search_vulnerabilities(i)
                    if results!=[]:
                        for score, vuln in results:
                            print(f"Score: {score}")
                            print(f"CVE ID: {vuln['cveID']}")
                            print(f"Vendor: {vuln['vendorProject']}")
                            print(f"Product: {vuln['product']}")
                            print(f"Vulnerability Name: {vuln['vulnerabilityName']}")
                            print(f"Description: {vuln['shortDescription']}")
                            print("-" * 30)
                    else:
                        print("No vulnerabilities to show")
                        pass
