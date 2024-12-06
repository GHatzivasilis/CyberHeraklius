
# Using calendar and time modules to read the current timestamp
import calendar;
import time;

# We need to create regular expressions to ensure that the input is correctly formatted.
import re

# Socket is the core mapping mechanism
import socket

# Multi-threaded process
import threading
from queue import Queue

# Store network scanning result in MariaDB
import mysql.connector

q = Queue()
nm = {"hostname": "", "state": "down", "ip": "", "timestamp": 0, "ports_tested": "", "ports_tested_num": 0, "ports": []}
ip_add_entered = ""

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

def threader():
	while True:
		examineport = q.get()
		global ip_add_entered
		singleportscanner(ip_add_entered, examineport)
		q.task_done()

def singleportscanner(ip_add_entered, port):
	#'''Check if port is open on host'''
	global nm
	gmt = time.gmtime() # gmt stores current gmtime
	ts1 = calendar.timegm(gmt) # ts stores timestamp
	socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	socket.setdefaulttimeout(1)
	result = socket_obj.connect_ex((ip_add_entered,port))
	socket_obj.close()
	gmt = time.gmtime() # gmt stores current gmtime
	ts2 = calendar.timegm(gmt) # ts stores timestamp
	newport = {"port": 0, "state": "", "name": "", "protocol": "", "product": "", "version": "", "extrainfo": "", "cpe": ""}
	scantime = ts2-ts1
	newport['extrainfo'] = str(scantime)
	if result == 0:
		newport['port'] = port
		newport['state'] = "open"
		nm['hostname'] = socket.gethostbyaddr(ip_add_entered)[0]
		newport['protocol'] = socket.getservbyport(port)
		nm['ports'].append(newport)
		print("open port detected: " + str(ip_add_entered) + " \t-- Port: " + str(port) + " \t-- Protocol: " + str(newport['protocol']) + " \t-- Hostname: " + str(nm['hostname']))
		nm['ports'].append(newport)
	else:
		nm['hostname'] = socket.gethostbyaddr(ip_add_entered)[0]
		protocol = ""
		try:
			protocol = socket.getservbyport(port)
			newport['port'] = port
			newport['state'] = "filtered"
			newport['protocol'] = protocol
			print("FILTERED port: " + str(ip_add_entered) + " \t-- Port: " + str(port) + " \t-- Protocol: " + str(newport['protocol']) + " \t-- Hostname: " + str(nm['hostname']))
			nm['ports'].append(newport)
		except:
			print("CLOSED port: " + str(ip_add_entered) + " \t-- Port: " + str(port) + " \t-- Protocol: " + str(newport['protocol']) + " \t-- Hostname: " + str(nm['hostname']))
	if nm['ports']!=[]:
		nm['state'] = 'up'
	#print("nm: ")
	#print(nm)

def mapNetwork(projectID, componentID, ip_entered, port_min, port_max):
    print('[INPUT] projectID: ', projectID)
    print('[INPUT] componentID: ', componentID)
    print('[INPUT] IP: ', ip_entered)
    print('[INPUT] port_min: ', port_min)
    print('[INPUT] port_max: ', port_max)
    
    global ip_add_entered
    global nm
    nm = {"hostname": "", "state": "down", "ip": "", "timestamp": 0, "ports_tested": str(port_min)+"-"+str(port_max), "ports_tested_num": port_max-port_min+1, "ports": []}
    ip_add_entered = ip_entered
    nm['ip'] = ip_add_entered
    
    # Perform scanning
    gmtTotal1 = time.gmtime() # gmtTotal stores current gmtime
    tsTotal1 = calendar.timegm(gmtTotal1) # ts stores timestamp
    nm['timestamp']=tsTotal1
    mutlithreadedportscanner(ip_add_entered, port_min, port_max)
    gmtTotal2 = time.gmtime() # gmtTotal stores current gmtime
    tsTotal2 = calendar.timegm(gmtTotal2) # ts stores timestamp
    print("nm: ")
    print(nm)
    print("Total time: " + str(tsTotal2-tsTotal1))
    
    # Create a connection to the database
    connection = create_connection()
    
    # Insert data into the table Nodes
    insert_data_query = "INSERT INTO Nodes (projectID, componentID, IP, timestamp, host, state, ports_tested, ports_tested_num) VALUES ('"+projectID+"', '"+componentID+"', '"+nm['ip']+"', "+str(tsTotal1)+", '"+nm['hostname']+"', '"+nm['state']+"', '"+nm['ports_tested']+"', "+str(nm['ports_tested_num'])+") ON DUPLICATE KEY UPDATE timestamp = "+str(tsTotal1)+", host = '"+nm['hostname']+"', state = '"+nm['state']+"', ports_tested = '"+nm['ports_tested']+"', ports_tested_num = "+str(nm['ports_tested_num'])+";"
    execute_query(connection, insert_data_query)
    
    for newport in nm['ports']:
    	print ('port : ', newport['port'])
    	print ('\t\tprotocol : ', newport['protocol'])
    	print ('\t\tstate : ', newport['state'])
    	print ('\t\tname: ', newport['name'])
    	print ('\t\tproduct: ', newport['product'])
    	print ('\t\tversion: ', newport['version'])
    	print ('\t\textrainfo: ', newport['extrainfo'])
    	print ('\t\tcpe: ', newport['cpe'])
    	# Insert data into the table Ports
    	insert_data_query = "INSERT INTO Ports (projectID, componentID, IP, port, state, name, protocol, product, version, extrainfo, cpe) VALUES ('"+projectID+"', '"+componentID+"', '"+ip_add_entered+"', "+str(newport['port'])+", '"+newport['state']+"', '"+newport['name']+"', '"+newport['protocol']+"', '"+newport['product']+"', '"+newport['version']+"', '"+newport['extrainfo']+"', '"+newport['cpe']+"') ON DUPLICATE KEY UPDATE state = '"+newport['state']+"', name = '"+newport['name']+"', protocol = '"+newport['protocol']+"', product = '"+newport['product']+"', version = '"+newport['version']+"', extrainfo = '"+newport['extrainfo']+"', cpe='"+newport['cpe']+"';"
    	execute_query(connection, insert_data_query)
    connection.close()
