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

def main():
    # Create a connection to the database
    connection = create_connection()

    # Drop table Port
    create_database_query = "DROP TABLE Ports"
    execute_query(connection, create_database_query)
    
    # Drop table Nodes
    create_database_query = "DROP TABLE Nodes"
    execute_query(connection, create_database_query)
    
    # Drop table Exploits
    create_database_query = "DROP TABLE Exploits"
    execute_query(connection, create_database_query)
    
    # Drop table CVEs
    create_database_query = "DROP TABLE CVEs"
    execute_query(connection, create_database_query)
    
    # Drop table CWEs
    create_database_query = "DROP TABLE CWEs"
    execute_query(connection, create_database_query)
    
    # Drop table CAPECs
    create_database_query = "DROP TABLE CAPECs"
    execute_query(connection, create_database_query)
    
    # Drop table Accounts
    create_database_query = "DROP TABLE Accounts"
    execute_query(connection, create_database_query)
    
    # Drop database
    create_database_query = "DROP DATABASE secoperadb"
    execute_query(connection, create_database_query)

if __name__ == "__main__":
    main()
