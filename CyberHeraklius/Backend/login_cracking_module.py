import subprocess
from flask import jsonify

# Store login cracking result in MariaDB
import mysql.connector

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
        print(f"The error '{e}' occurred")

#Perform the main logic cracking operation
def login_cracking(ip,service):
    # Define the command and parameters you would use with Hydra
    # For example, to attack an FTP server:
    # hydra -l user -P /path/to/password/list.txt ftp://target.ip
    
    target=service+":"+ip
    hydra_command = ["hydra", "-l", "user", "-P", "/path/to/password/list.txt", target]
    
    # Execute the command
    try:
    	result = subprocess.run(hydra_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    	# Process the output or errors
    	print(result.stdout.decode())
    	if result.stderr:
    		print(f"Errors: {result.stderr.decode()}")
    except subprocess.CalledProcessError as e:
    	print(f"Hydra encountered an error: {e}")
