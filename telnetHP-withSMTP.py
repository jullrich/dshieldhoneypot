import socket, time

def writelog(client, data=''):
	separator = '='*40
	fopen = open('potlog.txt', 'a')
	fopen.write('Time:%s,IP Address:%s,Port:%d,%s'%(time.ctime(), client[0], client[1], data))
	fopen.close()

def smtphp():
	ListenPort = 25

	serversocket = socket.socket(
	socket.AF_INET, socket.SOCK_STREAM)
	serversocket.bind((socket.gethostname(), ListenPort))
	serversocket.listen(5)

while 1:
	print "\n[*] Listening on port ", ListenPort
	conn, address = serversocket.accept()
	print "\n[*] Connection from ", address
	data = ""
	try:
			conn.send("220 computer ESMTP Server (Microsoft Exchange Internet Mail Service 4.0.994.63) ready\r\n")
	except:
			conn.close()

	while 1: #While the connection's open, accept commands and respond appropriately
		try:
			temp = conn.recv(1000000)
			data = data + temp
		except KeyboardInterrupt:
			print '\n\n[+] Exiting...'
			exit(0)
			break
		except socket.error, e:
			writelog(address)
		except:
			writelog(address, data)
			conn.close()
		if temp.count("HELO"):
			conn.send("250 computer\r\n")
		elif temp.count("EHLO"):
			conn.send("250 computer\r\n")
		elif temp.count("MAIL"):
			conn.send("250 Sender OK\r\n")
		elif temp.count("RCPT"):
			conn.send("250 Recipient OK.\r\n")
		elif temp.count("RSET"):
			conn.send("250 Ok resetting state\r\n")
		elif temp.count("DATA"):
			conn.send("354 Ok Send data ending with <CRLF>.<CRLF>\r\n")
		elif temp.count("."):
			conn.send("250 Message received\r\n")
		elif temp.count("QUIT"):
			conn.send("221 computer ESMTP server closing connection\r\n")
			writelog(address, data)
			break

		elif temp.count("HELP"):
			conn.send("""
			214-Commands:\r
			214-    HELO    EHLO    MAIL    RCPT    DATA\r
			214-    RSET    NOOP    QUIT    HELP    VRFY\r
			214-    EXPN\r  """)
		elif temp.count("VRFY"):
			conn.send("250\r\n")
		elif temp.count("NOOP"):
			conn.send("250\r\n")
		elif temp.count("EXPN"):
			conn.send("250\r\n")
		elif temp == "":
			break

def getstuff():
	banner = raw_input('\nEnter banner information: ')
	host = raw_input('Enter IP Address: ')
	while True or hp != null:
	try:
		port = int(raw_input('Enter Port Number: '))
	except TypeError:
		print '\n[-] Error: invalid port number\n'
		continue
	else:
		if (port < 1) or (port > 65535):
			print '\n[-] Error: invalid port number\n'
			continue
		else:
			return (banner, host, port)

def main(host, port, banner):
	if port == 25:
	hp = raw_input('Port 25 selected - do you want to initiate SMTP-Honeypot?')
	if hp in ("Y","y", "Yes", "Yea", "Si", "go", "Aye", "Sure"):
		smtphp()
	else:
		print '\n[*] Initating telnet honeypot .... \n[*] Listening ...\n'
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((host, port))
		s.listen(100)
		while True:
			(insock, address) = s.accept()
			print '[*] Connection from: %s:%d' % (address[0], address[1])
			try:
				insock.send('%s\n'%(banner))
				data = insock.recv(1024)
				insock.close()
			except socket.error, e:
				writelog(address)
			else:
				writelog(address, data)

if __name__=='__main__':
	try:
	stuff = getstuff()
	main(stuff[1], stuff[2], stuff[0])
	except KeyboardInterrupt:
	print '\n\n[+] Exiting...'
	exit(0)
	except BaseException, e:
	print '\n[-] Error: %s' % (e)
	exit(1)