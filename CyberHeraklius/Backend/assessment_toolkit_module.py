from flask import jsonify

# Store exploit search result in MariaDB
import mysql.connector

# Make Requests, process JSON objects, and Regular Expressions (RE)
import requests
import json
import re

# Using calendar and time modules to read the current timestamp
import calendar;
import time;

# Multi-threaded process
import threading
from queue import Queue

# Socket is the core mapping mechanism
import socket

# Imports for weak crypto test
import ssl
from ssl import SSLContext, PROTOCOL_TLS_CLIENT, CERT_NONE
from OpenSSL import SSL

# Process CWE and CAPEC webpages
from bs4 import BeautifulSoup

############### Port scanning parameters
q = Queue()
nm = {"hostname": "", "state": "down", "ip": "", "timestamp": 0, "ports_tested": "", "ports_tested_num": 0, "ports": []}
ip_add_entered = ""
full_scanning_result = False
scanning_test = False
############### Port scanning parameters
############### SecOPERA Databe endpoint
SecOPERA_url = "http://127.0.0.1:8000"
############### SecOPERA Databe endpoint

########################################### Database functions
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
        #print("Connection to MariaDB successful")
    except mysql.connector.Error as e:
        print(f"The error '{e}' occurred")
    return connection

def execute_query(connection, query):
    """Execute a given SQL query on the provided connection."""
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        #print("Query executed successfully")
    except mysql.connector.Error as e:
        print(f"Message '{e}'")
########################################### Database functions
########################################### Store to SecOPERA Database function
def getRisk(projectID, componentID):
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT MAX(impactScore) FROM CVEs WHERE projectID='"+projectID+"' AND componentID='"+componentID+"'")
    results = cursor.fetchall()
    
    risk = 0;
    if len(results) != 0:
    	risk=results[0][0]
    connection.close()
    return(risk)

def storeToSecOPERA(projectID, componentID):
    url = SecOPERA_url+'/api/tools/results/'+projectID+'/'+componentID+'/S-8/NETWORK'
    data = []
    kpiResults = []
    response = requests.get("http://127.0.0.1:8000/cti_search/getCVEs?projectID="+projectID+"&componentID="+componentID)
    if response.status_code == 200:
        CVE_data = response.json()
        if CVE_data['results'] :
        	#response = requests.post(url, json=CVE_data)
        	data.append( CVE_data )
        	#print('CVEs: ', CVE_data['results'])
    
    response = requests.get("http://127.0.0.1:8000/cti_search/getCWEs?projectID="+projectID+"&componentID="+componentID)
    if response.status_code == 200:
        CWE_data = response.json()
        if CWE_data['results'] :
        	#response = requests.post(url, json=CWE_data)
        	data.append( CWE_data )
        	#print('CWEs: ', CWE_data['results'])
    
    response = requests.get("http://127.0.0.1:8000/cti_search/getCAPECs?projectID="+projectID+"&componentID="+componentID)
    if response.status_code == 200:
        CAPEC_data = response.json()
        if CAPEC_data['results'] :
        	#response = requests.post(url, json=CAPEC_data)
        	data.append( CAPEC_data )
        	#print('CAPECs: ', CAPEC_data['results'])
    
    risk = getRisk(projectID, componentID)
    kpiResults.append(jsonify({'kpiId': 'S3-KPI-1', 'testerAchievedValue': str(risk), 'devAchievedValue': '0'}).get_json())
    data2 = jsonify({'kpiResults': kpiResults, 'runs': data})
    
    response = requests.post(url, json=data2.get_json())
    print("----storeToSecOPERA: ")
    #print("Response: ", response)
    #print('*****************************************')
    #print("----storeToSecOPERA: ", data)
    #print('*****************************************')
    #print("**** **** Data2: ", data2.get_json())
########################################### Store to SecOPERA Database function
########################################### Check if CTI already exists in Database
def existingCVE(cveID):
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT timestamp, sourceIdentifier, published, lastModified, vulnStatus, description, baseSeverity, exploitabilityScore, impactScore, reference FROM CVEs WHERE cveID='"+cveID+"' LIMIT 1")
    results = cursor.fetchall()
    
    #print("Query results (CVE "+cveID+"):")
    #for row in results:
        #print(row)
    connection.close()
    return results

def existingCWE(cweID):
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    #cursor.execute("SELECT timestamp, description, sourceIdentifier, type, reference, likelihood FROM CWEs WHERE cweID='"+cweID+"' LIMIT 1")
    cursor.execute("SELECT timestamp, description, sourceIdentifier, type, reference FROM CWEs WHERE cweID='"+cweID+"' LIMIT 1")
    results = cursor.fetchall()
    
    #print("Query results (CWE "+cweID+"):")
    #for row in results:
        #print(row)
    connection.close()
    return results
    
def existingCAPEC(capecID):
    # Create a connection to the database
    connection = create_connection()
    # Query data from the table Nodes based on 'projectID'
    cursor = connection.cursor()
    cursor.execute("SELECT timestamp, title, description, likelihoodOfAttack, severity, reference FROM CAPECs WHERE capecID='"+capecID+"' LIMIT 1")
    results = cursor.fetchall()
    
    #print("Query results (CAPEC "+capecID+"):")
    #for row in results:
        #print(row)
    connection.close()
    return results
########################################### Check if CTI already exists in Database

########################################### Main Assessment function
def DoS_flooding_test(projectID, componentID, ip_entered):
    print('\tDoS_flooding_test()')
    port = 80
    for i in range(1,5):
    	print('-Perform DoS')
    	#time. sleep(1)
    	for i in range(1,5):
    		socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    		socket.setdefaulttimeout(1)
    		result = socket_obj.connect_ex((ip_add_entered,port))
    		socket_obj.close()
    		if result != 0:
    			try:
    				tmp = socket.gethostbyaddr(ip_add_entered)[0]
    			except:
    				tmp = ""
    				print('--DoS flooding test was unsuccessful')
    				return(False)
    			try:
    				protocol = socket.getservbyport(port)
    			except:
    				print('--DoS flooding test was unsuccessful')
    				return(False)
    return True


USERNAMES = ['admin', 'user']
WEAK_PASSWORDS = ['123456', 'password', '123456789', '12345', '12345678', 'qwerty', 'abc123', '111111', '123123', 'admin', 'letmein', 'welcome', 'monkey', 'login', 'passw0rd', 'qwertyuiop', '123321', '1q2w3e4r', '654321', 'superman', '1qaz2wsx', '123qwe', 'password1', 'iloveyou', '000000']

def login_cracking_test(projectID, componentID, ip_entered):
    print('\tlogin_cracking_test()')
    found_usernames = []
    found_passwords = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
    #ip_entered = 'https://datacorpus.marvel-platform.eu'
    #ip_entered = 'https://marvel-platform.eu/login?next=/'
    ip_entered = 'https://velopera.voxel.at/grafana/login'
    #USERNAMES = ['hatzivas']
    #WEAK_PASSWORDS = ['4MDre7ahdFXQyQy']
    
    #print("[IP:", ip_entered, "]")
    print("Try weak credentials: ")
    hasLoginService = True
    for user in USERNAMES:
    	if not hasLoginService:
    		break
    	for password in WEAK_PASSWORDS:
    		try:
    			session = requests.Session()
    			credentials = {'username': user, 'password': password}
    			# Make a POST request to the login URL with credentials and headers
    			response = session.post(ip_entered, data=credentials, headers=headers, allow_redirects=False)
    			
    			# Check the response
    			if response.status_code == 200 or response.status_code == 302:
    				# Assuming the login redirects on successful login or shows a page
    				if 'dashboard' in response.text or 'success' in response.text:
    					print("-", credentials, " --> Login likely successful")
    					found_usernames.append(user)
    					found_passwords.append(password)
    				else:
    					print("-", credentials, " --> Login failed")
    			else:
    				print("-", credentials, " --> Login failed")
    				#print(f"Failed to login, status code: {response.status_code}")
    			session.close()
    		except requests.RequestException as e:
    			print("Not login service")
    			hasLoginService = False
    			break
    		
    if found_usernames:
    	for i in range(len(found_usernames)):
    		print("Found account: ", found_usernames[i], " | ", found_passwords[i])
    	return True
    print('--Login cracking test was unsuccessful')
    return False

INSECURE_CIPHERS = ['TLS_AES_128_GCM_SHA256', 'DHE-RSA-AES128-GCM-SHA256', 'TLS_CHACHA20_POLY1305_SHA256', 'ECDHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-GCM-SHA256', 'PSK-AES128-CBC-SHA', 'CAMELLIA128-SHA', 'SEED-SHA', 'AES128-SHA', 'DHE-PSK-AES128-CBC-SHA', 'RSA-PSK-AES128-CBC-SHA', 'SRP-AES-128-CBC-SHA', 'SRP-RSA-AES-128-CBC-SHA', 'SRP-DSS-AES-128-CBC-SHA', 'PSK-AES256-CBC-SHA', 'CAMELLIA256-SHA', 'AES256-SHA', 'DHE-PSK-AES256-CBC-SHA', 'RSA-PSK-AES256-CBC-SHA', 'SRP-AES-256-CBC-SHA', 'SRP-RSA-AES-256-CBC-SHA', 'SRP-DSS-AES-256-CBC-SHA', 'ADH-CAMELLIA128-SHA', 'ADH-SEED-SHA', 'ADH-AES128-SHA', 'DHE-DSS-CAMELLIA128-SHA', 'DHE-RSA-CAMELLIA128-SHA', 'DHE-DSS-SEED-SHA', 'DHE-RSA-SEED-SHA', 'DHE-DSS-AES128-SHA', 'DHE-RSA-AES128-SHA', 'ADH-CAMELLIA256-SHA', 'ADH-AES256-SHA', 'DHE-DSS-CAMELLIA256-SHA', 'DHE-RSA-CAMELLIA256-SHA', 'DHE-DSS-AES256-SHA', 'DHE-RSA-AES256-SHA',  'ECDHE-ECDSA-AES256-SHA', 'ECDHE-RSA-AES256-SHA', 'AECDH-AES256-SHA', 'ECDHE-ECDSA-AES128-SHA', 'ECDHE-RSA-AES128-SHA', 'AECDH-AES128-SHA', 'ECDHE-PSK-AES256-CBC-SHA', 'ECDHE-PSK-AES128-CBC-SHA']

def test_insecure_ciphers(host, port=443):
    supported_ciphers = {}
    not_supported_ciphers = {}
    print("Checking for weak ciphers: ")
    for cipher in INSECURE_CIPHERS:
        try:
        	# Creating a context with a specific cipher
        	context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        	context.set_ciphers(cipher)
        	context.check_hostname = False
        	context.verify_mode = ssl.CERT_NONE
        	# Establishing a socket connection
        	with socket.create_connection((host, port)) as sock:
        		with context.wrap_socket(sock, server_hostname=host) as ssock:
        			handshake = ssock.do_handshake()
        			supported_ciphers[cipher] = 'Supported'
        			print("-", cipher, " --> Supported")
        			ssock.close()
        except Exception as e:
        	not_supported_ciphers[cipher] = 'Not Supported'
        	print("-", cipher, " --> Not Supported")
    #if not_supported_ciphers:
    	#print("Weak ciphers that are not supported: ")
    	#for cipher, result in not_supported_ciphers.items():
    		#print("-", cipher)
    return supported_ciphers

def weak_crypto_test(projectID, componentID, ip_entered):
    print('\tweak_crypto_test()')
    
    cipher_test_results = test_insecure_ciphers(ip_entered)
    if cipher_test_results:
    	for cipher, result in cipher_test_results.items():
    		print(f"{cipher}: {result}")
    	return True
    print('--Weak cryptography test was unsuccessful')
    return False

def assessment(projectID, componentID, ip_entered):
    print('==== Assessment Tests ====')
    print('[INPUT] projectID: ', projectID)
    print('[INPUT] componentID: ', componentID)
    print('[INPUT] IP: ', ip_entered)
    
    result1 = full_port_scanning_test(projectID, componentID, ip_entered, 75, 85) #max 65535
    if result1 is True:
    	print("--Full port scanning test was successful")
    	store_SecOPERA_CVE(projectID, componentID, ip_entered, "SecOPERA-CVE-1")
    
    result2 = DoS_flooding_test(projectID, componentID, ip_entered)
    if result2 is True:
    	print("--DoS flooding test was successful")
    	store_SecOPERA_CVE(projectID, componentID, ip_entered, "SecOPERA-CVE-2")
    
    result3 = login_cracking_test(projectID, componentID, ip_entered)
    if result3 is True:
    	print("--Login cracking test was successful")
    	store_SecOPERA_CVE(projectID, componentID, ip_entered, "SecOPERA-CVE-3")
    
    result4 = weak_crypto_test(projectID, componentID, ip_entered)
    if result4 is True:
    	print("--Weak cryptography test was successful")
    	store_SecOPERA_CVE(projectID, componentID, ip_entered, "SecOPERA-CVE-4")
    #return jsonify({'Full_port_scanning': 'True', 'DoS_flooding': 'False', 'Login_cracking': 'False', 'Weak_crypto': 'False'})
    results = {'Full_port_scanning': result1, 'DoS_flooding': result2, 'Login_cracking': result3, 'Weak_crypto': result4}
    return results
########################################### Main Assessment function

########################################### Port scanning test
def full_port_scanning_test(projectID, componentID, ip_entered, port_min, port_max):
    #print('[INPUT] projectID: ', projectID)
    #print('[INPUT] componentID: ', componentID)
    #print('[INPUT] IP: ', ip_entered)
    #print('[INPUT] port_min: ', port_min)
    #print('[INPUT] port_max: ', port_max)
    
    global ip_add_entered
    ip_add_entered = ip_entered
    
    global full_scanning_result
    global scanning_test
    scanning_test = False
    mutlithreadedportscanner(ip_add_entered, port_min, port_max)
    if full_scanning_result:
    	full_scanning_result = False
    	scanning_test = True
    	print('Start scanning ports')
    	mutlithreadedportscanner(ip_add_entered, port_min, port_max)
    	if full_scanning_result:
    		#print('Full scan was successfull')
    		return True
    return False

# Assisting function for parallel execution
def mutlithreadedportscanner(ip_add_entered, port_min, port_max):
	print_lock = threading.Lock()
	
	# number of threads are we going to allow for
	for x in range(4):
		t = threading.Thread(target=threader)
		# classifying as a daemon, so they it will
		# die when the main dies
		t.daemon = True
		# begins, must come after daemon definition
		t.start()
	start = time.time()
	# 10 jobs assigned.
	for examineport in range(port_min, port_max+1):
		q.put(examineport)
	# wait till the thread terminates. 
	q.join() 

# Assisting function for parallel execution
def threader():
	global full_scanning_result
	full_scanning_result = False
	while True:
		examineport = q.get()
		global ip_add_entered
		if singleportscanner(ip_add_entered, examineport) is True:
			full_scanning_result = True
		global scanning_test
		if scanning_test:
			print('port: ', examineport, ' -- ', full_scanning_result)
		q.task_done()

# Assisting function for parallel execution
def singleportscanner(ip_add_entered, port):
	#'''Check if port is open on host'''
	socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	socket.setdefaulttimeout(1)
	result = socket_obj.connect_ex((ip_add_entered,port))
	socket_obj.close()
	#print("Test", port)
	if result == 0:
		return(True)
	else:
		try:
			tmp = socket.gethostbyaddr(ip_add_entered)[0]
		except:
			tmp = ""
		try:
			protocol = socket.getservbyport(port)
			return(True)
		except:
			return(False)
###########################################

def store_SecOPERA_CVE(projectID, componentID, ip, cve_id):
    # Create a connection to the database
    connection = create_connection()
    
    gmtTotal = time.gmtime() # gmtTotal stores current gmtime
    tsTotal = calendar.timegm(gmtTotal) # ts stores timestamp
    
    cpe_id = "non-cpe:"+projectID+":"+componentID+":"+ip
    vulnStatus = "new"
    cve_description = ""
    baseSeverity = 1
    exploitabilityScore = 1
    impactScore = 1
    references = ""
    weaknesses = ['']
    #threats = ['']
    
    if cve_id == "SecOPERA-CVE-1": # Network Mapping
    	cve_description = "The Full Port Scanning vulnerability of a host refers to a security exposure where an attacker systematically scans all possible communication ports on a networked host to identify open or listening ports. This scanning activity is typically conducted using automated tools to map out a host’s network services, including identifying running services, service versions, and operating systems. Such comprehensive port scanning can reveal potential entry points for further exploitation, such as unsecured or weakly secured services. While not inherently malicious, the act of full port scanning can be a precursor to more targeted attacks and is often used by attackers to prepare for future breaches, making it critical for network administrators to monitor and mitigate unauthorized scanning activities."
    	baseSeverity = "LOW"
    	exploitabilityScore = 10
    	impactScore = 2
    	
    	weaknesses = ['CWE-200']
    	#threats = ['CAPEC-300', 'CAPEC-309', 'CAPEC-169', 'CAPEC-224', 'CAPEC-292', 'CAPEC-310', 'CAPEC-574', 'CAPEC-287', 'CAPEC-301', 'CAPEC-302']
    elif cve_id == "SecOPERA-CVE-2": # DoS Atacks
    	cve_description = "Denial of Service (DoS) attacks pose a significant vulnerability by overwhelming a system, network, or service with a flood of illegitimate requests, rendering it unavailable to legitimate users. These attacks exploit the limited capacity of computing resources, such as bandwidth, memory, or processing power, causing the targeted system to slow down or crash entirely. DoS attacks can disrupt business operations, lead to financial losses, and damage an organization’s reputation. In more severe cases, they can be a precursor to other malicious activities, such as data breaches, by creating distractions or vulnerabilities that attackers can exploit. Mitigating DoS attacks requires robust security measures, including traffic filtering, rate limiting, and implementing redundancy in critical systems."
    	baseSeverity = "MEDIUM"
    	exploitabilityScore = 10
    	impactScore = 4
    	
    	weaknesses = ['CWE-200', 'CWE-400', 'CWE-770', 'CWE-772', 'CWE-404']
    	#threats = ['CAPEC-325', 'CAPEC-227', 'CAPEC-469', 'CAPEC-125', 'CAPEC-130', 'CAPEC-482', 'CAPEC-486', 'CAPEC-488']
    elif cve_id == "SecOPERA-CVE-3": # Login Cracking
    	cve_description = "Login cracking vulnerability occurs when an authentication system is susceptible to attacks aimed at systematically guessing or brute-forcing login credentials. This vulnerability typically exists in systems that do not have adequate protections, such as rate limiting, CAPTCHA, or account lockout mechanisms, which are designed to thwart repeated login attempts. Attackers exploit this weakness by using automated tools to rapidly attempt various username and password combinations until they successfully gain access to an account. Once access is obtained, the attacker can potentially cause significant harm, including unauthorized access to sensitive data, impersonation of the legitimate user, or further exploitation of the system. To mitigate login cracking vulnerabilities, it is essential to implement strong password policies, multi-factor authentication, and mechanisms to detect and block automated login attempts."
    	baseSeverity = "HIGH"
    	exploitabilityScore = 10
    	impactScore = 7
    	
    	weaknesses = ['CWE-521', 'CWE-262', 'CWE-263', 'CWE-798', 'CWE-654', 'CWE-307', 'CWE-308', 'CWE-309', 'CWE-645', 'CWE-400', 'CWE-257', 'CWE-654']
    	#threats = ['CAPEC-575', 'CAPEC-70', 'CAPEC-49', 'CAPEC-16', 'CAPEC-55', 'CAPEC-565', 'CAPEC-600', 'CAPEC-2', 'CAPEC-112', 'CAPEC-114']
    elif cve_id == "SecOPERA-CVE-4": # Weak Cryptography
    	cve_description = "A service that supports weak or outdated ciphers is highly vulnerable to cryptographic attacks, compromising the confidentiality and integrity of the data it handles. Ciphers are algorithms used to encrypt and decrypt data, and their strength determines how well they can protect sensitive information during transmission. Weak or outdated ciphers, such as those with insufficient key lengths or known vulnerabilities, can be easily exploited by attackers using modern computing power. This exploitation can lead to decrypted communications, exposing sensitive information like login credentials, financial data, or personal details. Moreover, these vulnerabilities can be used as entry points for more sophisticated attacks, such as man-in-the-middle attacks, where an attacker intercepts and potentially alters the communication between two parties. To mitigate this risk, services must regularly update their cryptographic protocols, disable support for weak ciphers, and enforce the use of strong, up-to-date encryption standards."
    	baseSeverity = "LOW"
    	exploitabilityScore = 10
    	impactScore = 2
    	
    	weaknesses = ['CWE-326', 'CWE-327', 'CWE-693', 'CWE-1241', 'CWE-1240']
    	#threats = ['CAPEC-112', 'CAPEC-192', 'CAPEC-20', 'CAPEC-97']
    
    # Insert data into the table CVEs
    insert_data_query = "INSERT INTO CVEs (projectID, componentID, cpeID, cveID, timestamp, sourceIdentifier, published, lastModified, vulnStatus, description, baseSeverity, exploitabilityScore, impactScore, reference) VALUES ('"+projectID+"', '"+componentID+"', '"+cpe_id+"', '"+cve_id+"', "+str(tsTotal)+", 'SecOPERA', '"+str(tsTotal)+"', '"+str(tsTotal)+"', '"+vulnStatus+"', '"+cve_description+"', '"+baseSeverity+"', '"+str(exploitabilityScore)+"', '"+str(impactScore)+"', '"+references+"');"
    execute_query(connection, insert_data_query)
    connection.close()
    
    store_weaknesses(projectID, componentID, cve_id, weaknesses)
    #Store data to SecOPERA Database
    storeToSecOPERA(projectID, componentID)

def store_weaknesses(projectID, componentID, cve_id, weaknesses):
    for cwe in weaknesses:
    	print("\t\tweaknesses-value: ", cwe)
    	store_CWE_and_CAPECs(projectID, componentID, cve_id, cwe)

def store_CWE_and_CAPECs(projectID, componentID, cve_id, cwe):
    # Create a connection to the database
    connection = create_connection()
    
    gmtTotal = time.gmtime() # gmtTotal stores current gmtime
    tsTotal = calendar.timegm(gmtTotal) # ts stores timestamp
    
    cweNUM = re.search(r"CWE-(\d+)", cwe, re.IGNORECASE)
    cwe_id = str(cweNUM.group(1))
    reference = "https://cwe.mitre.org/data/definitions/"+str(cwe_id)+".html"
    cwe_source = "security@apache.org"
    cwe_type = "Primary"
    cwe_description = ""
    Likelihood_Of_Exploit = "Undefined"
    
    try:
        response = requests.get(reference)
        response.raise_for_status()  # This will raise an exception for HTTP errors
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        result = existingCWE(cwe)
        if(result):
        	timestamp = result[0][0]
        	cwe_description = result[0][1]
        	cwe_description = cwe_description.replace("'", "\\'").replace('"', '\\"').replace(';', r'\;')
        	cwe_source = result[0][2]
        	cwe_type = result[0][3]
        	reference = result[0][4]
        	#Likelihood_Of_Exploit = result[0][5]
        else:
        	# The description typically under div with id 'Description'
        	description_tag = soup.find(id="oc_"+str(cwe_id)+"_Description")
        	cwe_description = description_tag.get_text(strip=True)
        	cwe_description.replace("'", "\\'").replace('"', '\\"').replace(';', r'\;')
        	#print("==== CWE Description: ", cwe_description)
        	
        	# The description typically under div with id 'Likelihood_Of_Exploit'
        	Likelihood_Of_Exploit_tag = soup.find(id="oc_"+str(cwe_id)+"_Likelihood_Of_Exploit")
        	Likelihood_Of_Exploit = "Undefined"
        	if Likelihood_Of_Exploit_tag is not None:
        		Likelihood_Of_Exploit = Likelihood_Of_Exploit_tag.get_text(strip=True)
        	#print("==== Likelihood_Of_Exploit: ", Likelihood_Of_Exploit)
        
        # Insert data into the table CWEs
        #insert_data_query = "INSERT INTO CWEs (projectID, componentID, cveID, cweID, timestamp, description, sourceIdentifier, type, reference, likelihood) VALUES ('"+projectID+"', '"+componentID+"', '"+cve_id+"', '"+cwe+"', "+str(tsTotal)+", '"+cwe_description+"', '"+cwe_source+"', '"+cwe_type+"', '"+reference+"', '"+Likelihood_Of_Exploit+"');"
        insert_data_query = "INSERT INTO CWEs (projectID, componentID, cveID, cweID, timestamp, description, sourceIdentifier, type, reference) VALUES ('"+projectID+"', '"+componentID+"', '"+cve_id+"', '"+cwe+"', "+str(tsTotal)+", '"+cwe_description+"', '"+cwe_source+"', '"+cwe_type+"', '"+reference+"');"
        execute_query(connection, insert_data_query)
        connection.close()
        
        ## Find and store CAPECs ##
        # The description typically under div with id 'Related_Attack_Patterns'
        capec_tag = soup.find(id="oc_"+str(cwe_id)+"_Related_Attack_Patterns")
        #print("==== CWE Related Attact Patterns:",capec_tag.get_text(strip=True))
        results = capec_tag.find_all('td')
        
        counter=1
        capecID = ""
        for result in results:
        	if (counter% 2 == 0):
        		print("\t\t\tCAPEC-ID: ", capecID)
        		title = result.text.replace("'", "\\'").replace('"', '\\"').replace(';', r'\;')
        		print("\t\t\t\ttitle: ", title)
        		store_CAPEC(projectID, componentID, "CWE-"+cwe_id, capecID, title)
        	else:
        		capecID = result.text
        	counter = counter + 1
    except requests.HTTPError:
        return "Failed to retrieve CWE or CAPEC page - HTTP Error."
    except Exception as e:
        return "An error occurred: "+str(e)
    return "OK"

def store_CAPEC(projectID, componentID, cwe_id, fullcapec_id, title):
    capec_id_num = re.search(r"CAPEC-(\d+)", str(fullcapec_id), re.IGNORECASE)
    capec_id = capec_id_num.group(1)
    gmtTotal = time.gmtime() # gmtTotal stores current gmtime
    tsTotal = calendar.timegm(gmtTotal) # ts stores timestamp
    
    url = "http://capec.mitre.org/data/definitions/"+str(capec_id)+".html"
    title = ""
    capec_description = ""
    likelihoodOfAttack = ""
    severity = ""
    
    try:
        # Create a connection to the database
        connection = create_connection()
        
        result = existingCAPEC(fullcapec_id)
        if(result):
        	timestamp = result[0][0]
        	title = result[0][1]
        	title = title.replace("'", "\\'").replace('"', '\\"').replace(';', r'\;')
        	capec_description = result[0][2]
        	capec_description = capec_description.replace("'", "\\'").replace('"', '\\"').replace(';', r'\;')
        	likelihoodOfAttack = result[0][3]
        	severity = result[0][4]
        	#url = result[0][5]
        else:
        	response = requests.get(url)
        	response.raise_for_status()  # This will raise an exception for HTTP errors
        	
        	# Parse the HTML content
        	soup = BeautifulSoup(response.text, 'html.parser')
        	
        	# The description typically under div with id 'Description'
        	description_tag = soup.find(id="oc_"+str(capec_id)+"_Description")
        	capec_description = description_tag.get_text(strip=True)
        	capec_description = capec_description.replace("'", "\\'").replace('"', '\\"').replace(';', r'\;')
        	#print("\t\t\t==== CAPEC Description: ", capec_description)
        	
        	# The description typically under div with id 'Likelihood Of Attack'
        	description_tag = soup.find(id="oc_"+str(capec_id)+"_Likelihood Of Attack")
        	likelihoodOfAttack = 'Undefined'
        	if description_tag is not None:
        		likelihoodOfAttack = description_tag.get_text(strip=True)
        	#print('CAPEC Likelihood Of Attack: ', likelihoodOfAttack)
        	#print("\t\t\t==== CAPEC Likelihood Of Attack: ", likelihoodOfAttack)
        	
        	# The description typically under div with id 'Typical Severity'
        	description_tag = soup.find(id="oc_"+str(capec_id)+"_Typical Severity")
        	severity = 'Undefined'
        	if description_tag is not None:
        		severity = description_tag.get_text(strip=True)
        	#print("\t\t\t==== CAPEC Typical Severity: ", severity)
        	
        	##results = description_tag.find_all('td')
        
        # Insert data into the table CAPECs
        insert_data_query = "INSERT INTO CAPECs (projectID, componentID, cweID, capecID, timestamp, title, description, likelihoodOfAttack, severity, reference) VALUES ('"+projectID+"', '"+componentID+"', '"+cwe_id+"', '"+fullcapec_id+"', "+str(tsTotal)+", '"+title+"', '"+capec_description+"', '"+likelihoodOfAttack+"', '"+severity+"', '"+url+"');"
        #print('CAPEC entry', insert_data_query)
        execute_query(connection, insert_data_query)
        connection.close()
    except requests.HTTPError:
        return "Failed to retrieve CAPEC page - HTTP Error."
    except Exception as e:
        return "An error occurred: "+str(e)
    return "OK"
