from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin

import sys
# using calendar and time modules to read the current timestamp
import calendar;
import time;

# Import nmap so we can use it for the scan
import nmap
# We need to create regular expressions to ensure that the input is correctly formatted.
import re

# Connect to local MariaDB
import mysql.connector

# Module that performs the main network mapping with Nmap and stores the data in the MariaDB
import network_mapping_module

# Module that performs the main exploit search with MetaSploit and stores the data in the MariaDB
import exploit_search_module

# Module that performs the main login cracking with Hydra and stores the data in the MariaDB
import login_cracking_module

# Module that performs the main Network Assessment tests and stores the data in the MariaDB
import assessment_toolkit_module

SecOPERA_url = "http://127.0.0.1:8000"

port_min = 0
port_max = 65535

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['CORS_HEADERS'] = 'Content-Type'

@app.route('/')
def hello():
    return 'SecOPERA Network Assessment'

#### Assessment Toolkit ####
@app.route('/network_assessment', methods=['GET'])
def network_assessment():
    
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    ip = request.args.get('ip', '')
    
    #TEST storeToSecOPERA()
    #assessment_toolkit_module.SecOPERA_url = SecOPERA_url
    #assessment_toolkit_module.storeToSecOPERA(projectID, componentID)
    #return("True")
    
    #print("SecOPERA_url", SecOPERA_url)
    assessment_toolkit_module.SecOPERA_url = SecOPERA_url
    results = assessment_toolkit_module.assessment(projectID, componentID, ip)
    
    # If the IP is valid, return the network assessment result
    return jsonify({'projectID': projectID, 'componentID': componentID, 'ip': ip, 'results': results})
#### Assessment Toolkit ####

#### Login Cracking ####
@app.route('/login_cracking', methods=['GET'])
def login_cracking():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    ip = request.args.get('ip', '')
    
    # Extract the service from query parameters
    service = request.args.get('service', '')
    
    # Perform login cracking with Hydra based on the given IP and service
    login_cracking_module.login_cracking(ip,service)
    
    # If the IP and service are valid, return the login cracking result
    return jsonify({'projectID': projectID, 'componentID': componentID, 'ip': ip, 'service': service})

@app.route('/login-cracking/getaccounts', methods=['GET'])
def login_cracking_getaccounts():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM Accounts WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Found Accounts for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the found accounts for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': results})

@app.route('/login-cracking/getaccountsnum', methods=['GET'])
def login_cracking_getaccountsnum():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(username) FROM Accounts WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Found Accounts number for project"+projectID+"|"+componentID+"):")
    num=0
    if len(results) != 0:
    	num=results[0][0]
    #print("Num: ", num)
    connection.close()
    
    # Return the number of found accounts for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': num})

@app.route('/login-cracking/getaccountsip', methods=['GET'])
def login_cracking_getaccountsip():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    ip = request.args.get('ip', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM Accounts WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND ip='"+ip+"'")
    results = cursor.fetchall()
    #print("Query results (Found Accounts for project"+projectID+"|"+componentID+"|"+ip+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the found accounts for a given Project ID and Version and IP
    return jsonify({'projectID': projectID, 'componentID': componentID, 'ip': ip, 'results': results})

@app.route('/login-cracking/getaccountsipnum', methods=['GET'])
def login_cracking_getaccountsipnum():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    ip = request.args.get('ip', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(username) FROM Accounts WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND ip='"+ip+"'")
    results = cursor.fetchall()
    #print("Query results (Found Accounts number for project"+projectID+"|"+componentID+"|"+ip+"):")
    num=0
    if len(results) != 0:
    	num=results[0][0]
    #print("Num: ", num)
    connection.close()
    
    # Return the number of found accounts for a given Project ID and Version and IP
    return jsonify({'projectID': projectID, 'componentID': componentID, 'ip': ip, 'results': num})

@app.route('/login-cracking/getaccountsipservice', methods=['GET'])
def login_cracking_getaccountsipservice():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    ip = request.args.get('ip', '')
    
    # Extract the service from query parameters
    service = request.args.get('service', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM Accounts WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND ip='"+ip+"' AND service='"+service+"'")
    results = cursor.fetchall()
    #print("Query results (Found Accounts for project"+projectID+"|"+componentID+"|"+ip+"|"+service+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the found accounts for a given Project ID and Version and IP and service
    return jsonify({'projectID': projectID, 'componentID': componentID, 'ip': ip, 'service': service, 'results': results})

@app.route('/login-cracking/getaccountsipservicenum', methods=['GET'])
def login_cracking_getaccountsipservicenum():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    ip = request.args.get('ip', '')
    
    # Extract the service from query parameters
    service = request.args.get('service', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(username) FROM Accounts WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND ip='"+ip+"' AND service='"+service+"'")
    results = cursor.fetchall()
    #print("Query results (Found Accounts number for project"+projectID+"|"+componentID+"|"+ip+"|"+service+"):")
    num=0
    if len(results) != 0:
    	num=results[0][0]
    #print("Num: ", num)
    connection.close()
    
    # Return the number of found accounts for a given Project ID and Version and IP and service
    return jsonify({'projectID': projectID, 'componentID': componentID, 'ip': ip, 'service': service, 'results': num})
#### Login Cracking ####

#### CTI Seacrh ####
@app.route('/cti_search', methods=['GET'])
def cti_search():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the CPE ID from query parameters
    cpeID = request.args.get('cpeID', '')
    
    # Search for exploits in the NIST's NVD based on the given cpeID
    exploit_search_module.SecOPERA_url = SecOPERA_url
    exploit_search_module.cti_search(projectID, componentID, cpeID)
    
    # If the cpeID is valid, return the CVE search result
    return jsonify({'projectID': projectID, 'componentID': componentID, 'cpeID': cpeID})


@app.route('/cti_search/getOverview', methods=['GET'])
def cti_search_getOverview():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT MAX(impactScore) FROM CVEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    
    risk = 0;
    if len(results) != 0:
    	risk=results[0][0]
    
    
    cveLow = 0;
    cveMed = 0;
    cveHigh = 0;
    cveCritical = 0;
    
    cursor.execute("SELECT COUNT(cveID) FROM CVEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND baseSeverity='LOW'")
    results = cursor.fetchall()
    if len(results) != 0:
    	cveLow=results[0][0]
    cursor.execute("SELECT COUNT(cveID) FROM CVEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND baseSeverity='MEDIUM'")
    results = cursor.fetchall()
    if len(results) != 0:
    	cveMed=results[0][0]
    cursor.execute("SELECT COUNT(cveID) FROM CVEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND baseSeverity='HIGH'")
    results = cursor.fetchall()
    if len(results) != 0:
    	cveHigh=results[0][0]
    cursor.execute("SELECT COUNT(cveID) FROM CVEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND baseSeverity='CRITICAL'")
    results = cursor.fetchall()
    if len(results) != 0:
    	cveCritical=results[0][0]
    
    cweLow = 0;
    cweMed = 0;
    cweHigh = 0;  
    cweCritical = 0;
    
    cursor.execute("SELECT COUNT(cweID) FROM CWEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    if len(results) != 0:
    	cweLow=results[0][0]
    	
    capecLow = 0;
    capecMed = 0;
    capecHigh = 0;
    capecCritical = 0;
    
    cursor.execute("SELECT COUNT(capecID) FROM CAPECs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND severity='LOW'")
    results = cursor.fetchall()
    if len(results) != 0:
    	capecLow=results[0][0]
    cursor.execute("SELECT COUNT(capecID) FROM CAPECs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND severity='MEDIUM'")
    results = cursor.fetchall()
    if len(results) != 0:
    	capecMed=results[0][0]
    cursor.execute("SELECT COUNT(capecID) FROM CAPECs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND severity='HIGH'")
    results = cursor.fetchall()
    if len(results) != 0:
    	capecHigh=results[0][0]
    cursor.execute("SELECT COUNT(capecID) FROM CAPECs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND severity='CRITICAL'")
    results = cursor.fetchall()
    if len(results) != 0:
    	capecCritical=results[0][0]
    
    exploitLow = 0;
    exploitMed = 0;
    exploitHigh = 0;
    exploitCritical = 0;
    
    cursor.execute("SELECT COUNT(fullname) FROM Exploits WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    if len(results) != 0:
    	exploitCritical=results[0][0]
    #print("exploitCritical: ", exploitCritical)
    connection.close()
    
    # Return the exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'risk': risk, 'cveLow': cveLow, 'cveMed': cveMed, 'cveHigh': cveHigh, 'cveCritical': cveCritical, 'cweLow': cweLow, 'cweMed': cweMed, 'cweHigh': cweHigh, 'cweCritical': cweCritical, 'capecLow': capecLow, 'capecMed': capecMed, 'capecHigh': capecHigh, 'capecCritical': capecCritical, 'exploitLow': exploitLow, 'exploitMed': exploitMed, 'exploitHigh': exploitHigh, 'exploitCritical': exploitCritical})

@app.route('/cti_search/getCPECVEs', methods=['GET'])
def cti_search_getCPECVEs():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the CPE ID from query parameters
    cpeID = request.args.get('cpeID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM CVEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND cpeID='"+cpeID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'cpeID': cpeID, 'results': results})

@app.route('/cti_search/getCVEs', methods=['GET'])
def cti_search_getCVEs():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM CVEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': results})

@app.route('/cti_search/getCVECWEs', methods=['GET'])
def cti_search_getCVECWEs():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the CVE ID from query parameters
    cveID = request.args.get('cveID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM CWEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND cveID='"+cveID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'cveID': cveID, 'results': results})

@app.route('/cti_search/getCWEs', methods=['GET'])
def cti_search_getCWEs():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM CWEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': results})

@app.route('/cti_search/getCWECAPECs', methods=['GET'])
def cti_search_getCWECAPECs():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the CWE ID from query parameters
    cweID = request.args.get('cweID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM CAPECs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND cweID='"+cweID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'cweID': cweID, 'results': results})

@app.route('/cti_search/getCAPECs', methods=['GET'])
def cti_search_getCAPECs():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM CAPECs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': results})
#### CVE Seacrh ####

#### Exploit Seacrh ####
@app.route('/exploit_search', methods=['GET'])
def exploit_search():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the CVE ID from query parameters
    cveID = request.args.get('cveID', '')
    
    # Search for exploits in the MetaSploit framework based on the given projectID, componentID, cveID
    exploit_search_module.exploit_search(projectID, componentID, cveID)
    
    # If the cveID is valid, return the exploit search result
    return jsonify({'projectID': projectID, 'componentID': componentID, 'cveID': cveID})

@app.route('/exploit_search/getexploits', methods=['GET'])
def exploit_search_getexploits():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM Exploits WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': results})

@app.route('/exploit_search/getexploitsnum', methods=['GET'])
def exploit_search_getexploitsnum():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(fullname) FROM Exploits WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits number for project"+projectID+"|"+componentID+"):")
    num=0
    if len(results) != 0:
    	num=results[0][0]
    #print("Num: ", num)
    connection.close()
    
    # Return the number of exploits for a given Project ID and Version
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': num})

@app.route('/exploit_search/getcveexploits', methods=['GET'])
def exploit_search_getcveexploits():
    # Extract the CVE ID from query parameters
    cveID = request.args.get('cveID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Exploits based on 'cveID'
    cursor = connection.cursor()
    cursor.execute("SELECT DISTINCT fullname, name, type, rank, disclosuredate FROM Exploits WHERE cveID='"+cveID+"'")
    results = cursor.fetchall()
    #print("Query results (Exploits for CVE "+cveID+")")
    #for row in results:
        #print(row)
    connection.close()
    
    # Return the exploits for a given CVE ID
    return jsonify({'cveID': cveID, 'results': results})
#### Exploit Seacrh ####

#### Network Mapping ####
@app.route('/network_mapping', methods=['GET'])
def network_mapping():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP address from query parameters
    ip_address = request.args.get('ip', '')
    # Validate the IP address (basic validation)
    if not ip_address or not validate_ip(ip_address):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    # Extract the port range from query parameters
    port_range = request.args.get('ports', '')
    # Validate the port range
    if not port_range or not validate_port_range(port_range):
        return jsonify({'error': 'Invalid port range -- designated format: <int>-<int>'}), 400
    
    global port_min
    global port_max
    network_mapping_module.mapNetwork(projectID,componentID,ip_address,port_min,port_max)
    
    # If the IP is valid, return it back in the response
    return jsonify({'projectID': projectID, 'componentID': componentID, 'IP': ip_address, 'port_range': port_range})

#Assisting functions for 'network_mapping()'
def validate_ip(ip):
    # Basic validation to check IP format
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for item in parts:
        if not item.isdigit() or not 0 <= int(item) <= 255:
            return False
    return True

def validate_port_range(port_range):
    # Regular Expression Pattern to extract the number of ports you want to scan. 
    # You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    # Initialising the port numbers, will be using the variables later on.
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        global port_min
        port_min = int(port_range_valid.group(1))
        global port_max
        port_max = int(port_range_valid.group(2))
        return True
    return False
#Assisting functions for 'network_mapping()'

@app.route('/network_mapping/getnodes', methods=['GET'])
def network_mapping_getnoedes():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT timestamp, IP, host, state, ports_tested, ports_tested_num FROM Nodes WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Nodes for project"+projectID+"|"+componentID+"):")
    #for row in results:
        #print(row)
    connection.close()
    
    # If the IP is valid, return it back in the response
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': results})

@app.route('/network_mapping/getnodesnum', methods=['GET'])
def network_mapping_getnoedesnum():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(projectID) FROM Nodes WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    #print("Query results (Nodes-count):")
    num=0
    if len(results) != 0:
    	num=results[0][0]
    #print("Num: ", num)
    connection.close()
    
    # If the IP is valid, return it back in the response
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': num})

@app.route('/network_mapping/getnodeports', methods=['GET'])
def network_mapping_getnodeports():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    IP = request.args.get('IP', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Ports based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT port, state, name, protocol, product, version, extrainfo, cpe FROM Ports WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND IP='"+IP+"'")
    results = cursor.fetchall()
    #print("Query results (Ports):", results)
    #for row in results:
        #print(row)
    connection.close()
    
    # If the IP is valid, return it back in the response
    return jsonify({'projectID': projectID, 'componentID': componentID, 'IP': IP, 'results': results})

@app.route('/network_mapping/updatenodeports', methods=['GET'])
def network_mapping_updatenodeports():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    IP = request.args.get('IP', '')
    
    # Extract the port from query parameters
    port = request.args.get('port', '')
    
    # Extract the name from query parameters
    new_name = request.args.get('name', '')
    
    # Extract the product from query parameters
    new_product = request.args.get('product', '')
    
    # Extract the version from query parameters
    new_version = request.args.get('version', '')
    
    # Extract the cpeID from query parameters
    new_cpeID = request.args.get('cpeID', '')
    
    #print("port: ", port)
    #print("cpeID: ", new_cpeID)
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Ports based on 'projectID'
    #cursor = connection.cursor()
    
    update_query = f"""
    UPDATE Ports
    SET name = '{new_name}', product = '{new_product}', version = '{new_version}', cpe = '{new_cpeID}'
    WHERE projectID = '{projectID}' AND componentID = '{componentID}' AND IP = '{IP}' AND port = {port}
    """
    results = execute_query(connection, update_query)
    
    connection.close()
    
    # Return if the update was performed or not
    return jsonify({'projectID': projectID, 'componentID': componentID, 'IP': IP, 'port': port, 'results': results})

@app.route('/network_mapping/getnodeportsnum', methods=['GET'])
def network_mapping_getnodeportsnum():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Extract the IP from query parameters
    IP = request.args.get('IP', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Ports based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(port) FROM Ports WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND IP='"+IP+"'")
    results = cursor.fetchall()
    #print("Query results (ports-count):")
    num=0
    if len(results) != 0:
    	num=results[0][0]
    #print("Num: ", num)
    connection.close()
    
    # If the IP is valid, return it back in the response
    return jsonify({'projectID': projectID, 'componentID': componentID, 'IP': IP, 'results': num})

@app.route('/network_mapping/getopenportsnum', methods=['GET'])
def network_mapping_getopenportsnum():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Ports based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(port) FROM Ports WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND state='open'")
    results = cursor.fetchall()
    #print("Query results (open-ports-count):")
    num=0
    if len(results) != 0:
    	num=results[0][0]
    #print("Num: ", num)
    connection.close()
    
    # If the IP is valid, return it back in the response
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': num})

@app.route('/network_mapping/getfilteredportsnum', methods=['GET'])
def network_mapping_getfilteredportsnum():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Extract the componentID from query parameters
    componentID = request.args.get('componentID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Ports based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(port) FROM Ports WHERE projectID='"+projectID+"' AND componentID='"+componentID+"' AND state='filtered'")
    results = cursor.fetchall()
    #print("Query results (filtered-ports-count):")
    num=0
    if len(results) != 0:
    	num=results[0][0]
    #print("Num: ", num)
    connection.close()
    
    # If the IP is valid, return it back in the response
    return jsonify({'projectID': projectID, 'componentID': componentID, 'results': num})

@app.route('/network_mapping/getmappinghistory', methods=['GET'])
def network_mapping_getmappinghistory():
    # Extract the projectID from query parameters
    projectID = request.args.get('projectID', '')
    
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Ports based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT componentID, IP, ports_tested, timestamp FROM Nodes WHERE projectID='"+projectID+"'")
    results = cursor.fetchall()
    #print("Query results (mapping-history):")
    #for row in results:
        #print(row)
    connection.close()
    
    # If the IP is valid, return it back in the response
    return jsonify({'projectID': projectID, 'results': results})
#### Network Mapping ####

#### Database functions ####
def create_connection():
    """Create a database connection."""
    connection = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='secoperauser',  # Use your username
            passwd='secSMNd4a5!',    # Use your password
            database='secoperabase'  # The database to connect to, will be created if it doesn't exist
        )
        print("Connection to MariaDB successful")
    except mysql.connector.Error as e:
        print(f"The error '{e}' occurred")
    return connection

def execute_query(connection, query):
    """Execute a given SQL query on the provided connection."""
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        print("Query executed successfully")
    except mysql.connector.Error as e:
        print(f"Message '{e}'")
#### Database functions ####

#### Test function -- Store to SecOPERA Database ####
@app.route('/api/tools/results/<projectId>/<componentId>/<toolId>/<layer>', methods=['POST'])
def post_data(projectId, componentId, toolId, layer):
    # Check if JSON data is sent with the request
    if request.is_json:
        # Parse the JSON data
        data = request.get_json()

        # Process the data (example: just echoing it back with URL params)
        response = {
            "message": "Data received",
            "projectId": projectId,
            "componentId": componentId,
            "toolId": toolId,
            "layer": layer,
            "Data": data
        }
        print("******************")
        print("******************")
        print("******************")
        print("******************")
        print("******************")
        print("Response: ", response)
        return jsonify(response), 200
    else:
        return jsonify({"error": "Request must be JSON"}), 400

#### MAIN function ####
if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) == 2:
    	if args[0] == "--SecOPERA_url":
    		SecOPERA_url = args[1]
    app.run(host='0.0.0.0', debug=True, port=8000, threaded=True)
