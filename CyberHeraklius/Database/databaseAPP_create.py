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

    # Create a new database
    create_database_query = "CREATE DATABASE IF NOT EXISTS secoperadb"
    execute_query(connection, create_database_query)

    # Create a new table Nodes
    create_table_query = """
    CREATE TABLE IF NOT EXISTS Nodes (
        projectID VARCHAR(50) NOT NULL, 
        componentID VARCHAR(50) NOT NULL, 
        IP VARCHAR(15) NOT NULL, 
        timestamp INT, 
        host VARCHAR(50), 
        state VARCHAR(50), 
        ports_tested VARCHAR(11), 
        ports_tested_num INT, 
        PRIMARY KEY (projectID, componentID, IP)
    ) ENGINE = InnoDB
    """
    execute_query(connection, create_table_query)
    
    # Create a new table Ports
    create_table_query = """
    CREATE TABLE IF NOT EXISTS Ports (
        projectID VARCHAR(50) NOT NULL, 
        componentID VARCHAR(50) NOT NULL, 
        IP VARCHAR(15) NOT NULL, 
        port INT NOT NULL, 
        state ENUM('open','filtered','close')DEFAULT 'close', 
        name VARCHAR(50), 
        protocol VARCHAR(50), 
        product VARCHAR(50), 
        version VARCHAR(50), 
        extrainfo VARCHAR(50), 
        cpe VARCHAR(100), 
        PRIMARY KEY (projectID, componentID, IP, port),
        FOREIGN KEY (projectID, componentID, IP) REFERENCES Nodes(projectID, componentID, IP)
    ) ENGINE = InnoDB
    """
    execute_query(connection, create_table_query)
    
    # Create a new table Exploits
    create_table_query = """
    CREATE TABLE IF NOT EXISTS Exploits (
        projectID VARCHAR(50) NOT NULL, 
        componentID VARCHAR(50) NOT NULL, 
        cveID VARCHAR(20) NOT NULL, 
        timestamp INT, 
        fullname VARCHAR(80), 
        name VARCHAR(200), 
        type VARCHAR(15), 
        rank VARCHAR(5015), 
        disclosuredate VARCHAR(10), 
        PRIMARY KEY (projectID, componentID, cveID, fullname)
    ) ENGINE = InnoDB
    """
    execute_query(connection, create_table_query)
    
    # Create a new table CVEs
    create_table_query = """
    CREATE TABLE IF NOT EXISTS CVEs (
        projectID VARCHAR(50) NOT NULL, 
        componentID VARCHAR(50) NOT NULL, 
        cpeID VARCHAR(50) NOT NULL, 
        cveID VARCHAR(50) NOT NULL, 
        timestamp INT, 
        sourceIdentifier VARCHAR(25), 
        published VARCHAR(25), 
        lastModified VARCHAR(25), 
        vulnStatus VARCHAR(15), 
        description VARCHAR(2500),
        baseSeverity VARCHAR(20), 
        exploitabilityScore VARCHAR(10), 
        impactScore VARCHAR(3), 
        reference VARCHAR(100),
        PRIMARY KEY (projectID, componentID, cpeID, cveID)
    ) ENGINE = InnoDB
    """
    execute_query(connection, create_table_query)
    
    # Create a new table CWEs
    create_table_query = """
    CREATE TABLE IF NOT EXISTS CWEs (
        projectID VARCHAR(50) NOT NULL, 
        componentID VARCHAR(50) NOT NULL, 
        cveID VARCHAR(50) NOT NULL, 
        cweID VARCHAR(14) NOT NULL, 
        timestamp INT, 
        description VARCHAR(2500), 
        sourceIdentifier VARCHAR(25), 
        type VARCHAR(15), 
        reference VARCHAR(100),
        likelihood VARCHAR(10),
        PRIMARY KEY (projectID, componentID, cveID, cweID)
    ) ENGINE = InnoDB
    """
    execute_query(connection, create_table_query)
    
    # Create a new table CAPECs
    create_table_query = """
    CREATE TABLE IF NOT EXISTS CAPECs (
        projectID VARCHAR(50) NOT NULL, 
        componentID VARCHAR(50) NOT NULL, 
        cweID VARCHAR(14) NOT NULL, 
        capecID VARCHAR(10) NOT NULL, 
        timestamp INT, 
        title VARCHAR(150),
        description VARCHAR(2500),
        likelihoodOfAttack VARCHAR(10),
        severity VARCHAR(20), 
        reference VARCHAR(100),
        PRIMARY KEY (projectID, componentID, cweID, capecID)
    ) ENGINE = InnoDB
    """
    execute_query(connection, create_table_query)
    
    # Create a new table Nodes
    create_table_query = """
    CREATE TABLE IF NOT EXISTS Accounts (
        projectID VARCHAR(50) NOT NULL, 
        componentID VARCHAR(50) NOT NULL, 
        IP VARCHAR(15) NOT NULL, 
        service VARCHAR(10) NOT NULL, 
        username VARCHAR(20) NOT NULL, 
        password VARCHAR(20), 
        timestamp INT, 
        PRIMARY KEY (projectID, componentID, IP, service, username)
    ) ENGINE = InnoDB
    """
    execute_query(connection, create_table_query)

if __name__ == "__main__":
    main()
