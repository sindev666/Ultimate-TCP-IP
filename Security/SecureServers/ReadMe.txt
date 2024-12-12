// =================================================================
// Dundas TCP/IP v4.0
// Copyright (C) Dundas Software 1995-2000, all rights reserved
// The programs included in this folder are provided as is 
// For testing purposes only.
// =================================================================

This folder contains a number of test servers provided to allow 
you to easily set up a server to test the client samples provided
 with Dundas TCP/IP

These samples were compiled with Dundas Security library.
To run them make sure you have the Security Layer Library of Dundas
 Software in the execution path of this programs. 

Although these servers are fully functional servers, only five concurrent
 users are allowed to connect to this server (for ease of use)

To test each one simply double-click on the program icon. These samples are
 demonstration programs. They are not intended to be fully blown servers. 

The Servers are:
1) Secure Echo Server (SecureEchoServer.exe)
	Provided to test the secure echo client as a demonstration of how to
 create a custom protocol using Dundas TCP/IP Enterprise Edition (security version)

	The server will be listening on port 777 for incoming secure connections. 
	To test this server, compile and run example located at 
		...[Dundas TCP/IP Install path]/Security/Examples/Clients/Echo/

2) Secure Http Server (SecureHTTPServer.exe) 
	Provided as a demonstration to test the secure HTTP client. The server will
 be listening on port 443 for incoming secure connections. 
	To test this server, compile and run example located at 
		...[Dundas TCP/IP Install path]/Security/Examples/Clients/HTTPS/
	Use your browser to open the following link
		https://127.0.0.1/index.htm
	where index.htm is a document that exist on the root directory as you set in the dialog

3) Secure FTP Server (secureFTPServer.exe)
	Provided to test the secure FTP client as a demonstration.
	The server will be listening on port 21 for incoming secure connections. 
	To test this server, compile and run example located at 
		...[Dundas TCP/IP Install path]/Security/Examples/Clients/FTPs/
	or Use your SSL/TLS enabled FTP client to open the following link
		host : 127.0.0.1
		username: anonymous
		password: (any string)

4) Secure Mail Server (SecureMailServer.exe) 
	Provided to test the secure Email client as a demonstration.
	The server will be listening on port 25 for incoming secure connections. 
	It will also be listening on port 110 for incoming pop3 connection
	To test this server, compile and run example located at 
		...[Dundas TCP/IP Install path]/Security/Examples/Clients/Mail/
	Use your SSL enabled email client to open the following 
		SMTP server : 127.0.0.1
		POP3 Server: 127.0.0.1
		user name and password: (use the config button on the server dialog to
 add users and aliases)

	Before you start the server make sure you have created the email root path.
	You will also need to create two sub folders named "QUE" and "0"

	You can use the provided test certificate by first installing it and selecting it
 from the certificate management browser by clicking the ... button



If you have any question please feel free to contact Dundas Tech Support at 
	tech@dundas.com






	
