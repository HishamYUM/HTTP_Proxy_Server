# HTTP_Proxy_Server
# HTTP-Proxy-Server-with-threadpool
In this project we implemented a C HTTP Proxy Server with threadpool and limited subset of the entire HTTP specification.
The proxy server gets an HTTP request from the client, and performs some predefined checks on it. If the request is found legal, it forwards the request to the appropriate web server, and sends the response back to the client. Otherwise, it send s a response to the client without sending anything to the server. Only IPv4 connections should be supported. This project written on Linux operating system on C.

Submitted Files
---------------
	proxyServer.c - an implementation for a basic TCP proxy server. 
	threadpool.c - an implementation of a threadpool.
	threadpool.h - header file with stracts of a threadpool.   
	filter.txt  - filter with list of sites that restrained for visiting.  
Assumptions:
--------------
We will relate only to the method GET (always in the first line), and the header Host (the headers of HTTP request are separated from the possible message by empty line; the Host doesn't have to be the first header!). We can ignore anything else.


Usage:
---------------

#### Test the code:
This project was wrote on Ubuntu (Linux) and run in the terminal.

#### Compile the proxy server:
makefile:  
&nbsp;&nbsp;&nbsp;&nbsp;all:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;gcc -Wall *.c threadpool.h -o proxyServer -lpthread  

Remember that you have to compile with the –lpthread flag.  -Wall option flag enables all compiler's warning messages. This option is used, in order to generate better code.




#### Running:
1. Command line to run the server:  <b>```./proxyServer <port> <pool-size> <max-number-of-request> <filter> ```</b>
