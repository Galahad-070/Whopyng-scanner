Whopyng-scanner: A Network Scanning Tool

Whopyng-scanner is a versatile network scanning tool designed to provide comprehensive information about network devices and their services. It combines essential network scanning functionalities with vulnerability detection, offering a robust solution for network analysis and security auditing.
Key Features

    Port Scanning: Identifies open TCP and UDP ports on target hosts, helping to understand the services running on a network.

    OS Detection: Attempts to detect the operating system of target devices, providing valuable context for further analysis.

    Vulnerability Detection: Checks identified services against a database of known exploited vulnerabilities to highlight potential security risks.

    Host Discovery: Pings a range of IP addresses to identify active hosts on the network.

    Multi-threading: Uses multi-threading to speed up the scanning process.

    Fuzzy matching: Uses fuzzy matching to improve vulnerability detection.

    IP Range Generation: Can generate a range of IP addresses from a given prefix.

How it Works

Whopyng-scanner operates by performing the following steps:

    Host Discovery: The scanner begins by identifying active hosts within a specified IP range using ping scans.

    Port Scanning: For each active host, the scanner probes TCP and UDP ports to determine which services are exposed.

    OS Detection: The scanner employs techniques like analyzing TCP/IP stack characteristics (TTL values) and ARP requests to guess the operating system of the target.

    Vulnerability Detection: The scanner uses fuzzy matching to compare the description of the services found on the open ports with known vulnerabilities from the CISA database.

    Output: The results of the scan, including open ports, OS information, and potential vulnerabilities, are displayed to the user.

Dependencies

The scanner relies on the following Python libraries and tools:

    flask: For the web interface.

    flask_cors: For handling Cross-Origin Resource Sharing (CORS).

    threading: For concurrent execution.

    queue: For managing data between threads.

    sys: For standard output redirection.

    io: For handling stream.

    socket: For network communication.

    subprocess: For running external commands.

    platform: For OS detection.

    scapy: For advanced packet manipulation (ARP, ICMP).

    mac_vendor_lookup: For determining device vendor from MAC address.

    json: For handling JSON data.

    fuzzywuzzy: For fuzzy string matching in vulnerability detection.

    ipaddress: For IP address manipulation.

Other required files

The scanner uses the following JSON files:

    ports.json: This file contains a list of ports and their descriptions.

        Source: `https://github.com/djcas9/ports.json/blob/master/ports.json`

    known_exploited_vulnerabilities.json: This file contains a list of known exploited vulnerabilities.

        Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Installation

    Install the required Python dependencies using pip install -r requirements.txt.

    Ensure you have network scanning privileges.

Usage

    Run the backend.py file.

    Open your browser to the specified address.

    Enter the target IP address and select the desired scan options.

    View the scan results.

Contributions

Contributions are welcome! Please submit pull requests or open issues to suggest improvements or report bugs.
