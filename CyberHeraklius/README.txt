
	==== SecOPERA - Network and Cross Layer penetration testing ====
			-- Description --
The Penetration Testing Toolkit performs the main SecOPERA assessments of this cross-layer analysis. At first, the user can perform network mapping in order to identify the elements that are deployed in the network and gather public CTI for known security problems (CVEs, CWEs, CAPECs, and Metasploit exploits). Thereupon, the user can execute a series of automated assessment tests, examining wherever the identified components/assets are vulnerable to: i) port scanning, ii) Denial of Service (DoS) attacks, iii) login cracking, or iv) weak cryptographic options. 


			-- Deployment Instrucitons --
1.For the deployment of the Network and Cross Layer penetration testing,
we need a native instalation of MariaDB in the host device. Here, are the
related commands.

==Install MariaDB==
i.Update Your Package Index: Before installing new software, it's a good
practice to update your package index to ensure you're installing the latest
versions of the software. Open a terminal and run:

  sudo apt update

ii.Install MariaDB: After updating the package index, you can install MariaDB by running:

  sudo apt install mariadb-server

This command installs the MariaDB server and the client packages.

iii.Secure MariaDB Installation: After installing MariaDB, it's recommended to run a 
ecurity script that comes with MariaDB. This script helps you secure your database system. Run:

  sudo mysql_secure_installation

The script will guide you through several security settings, including setting a password for the root user, removing anonymous users, disallowing root login remotely, and removing the test database.

iv.Start and Enable MariaDB Service: Ensure that the MariaDB service starts automatically upon system boot:

  sudo systemctl enable mariadb
  sudo systemctl start mariadb

v.Check MariaDB Service Status: To verify that MariaDB is running, use:

  sudo systemctl status mariadb

vii.Create SecOPERA database schemas for the three services of: i) network mapping, ii) exploit search, and iii) login cracking
  cd Database/
  sudo python databaseAPP_delete.py
  sudo python databaseAPP_create.py

2.The penetration testing toolkit itself has been dockerized in two parts for Backend and Fronend, respectively.

2.1 Run the Backend
  cd Backend/
  (if you want the toolkit to store results in the SecOPERA Database, edit the Docker file and set the SecOPERA_url in the last line (i.e., change the parameter "http://127.0.0.1:8000"):
  ...
  CMD ["python", "app.py", "--SecOPERA_url", "http://127.0.0.1:8000"] )

  docker build -t myflaskapp .
  docker run --network="host" -p 8000:8000 myflaskapp

2.1 Run the Frontend
  Finf the IP address of the machine (e.g, run the command: ip address)
  Edit the file /src/app/environments/environment.ts and set the machine's IP.

  cd Frontend/
  docker build -t myangularapp .
  docker run --network="host" -p 4200:4200 myangularapp

3.To check if the service is running, open a browser and try the following URL:
  http://[Machine IP]:4200/

4.In order for the service to be accessible from outside, you may have to open the
related port in the VMs firewall. For example:

  sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 4200 -j ACCEPT

