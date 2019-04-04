from imports import *

def main():
	active_threads = []
	logger.log("proxy launched")
	logger.log("creating server socket...")
	server = socket(AF_INET, SOCK_STREAM)
	logger.log("binding socket to port " + str(config.proxy_port) + "...")
	server.bind((config.proxy_ip, config.proxy_port))
	server.listen(8)
	logger.log("listening to incoming requests...")
	signal.signal(signal.SIGINT, shutdown_proxy)
	def signal_handler(signal, frame):
		server.shutdown(SHUT_RDWR)
		server.close()
		sys.exit(0)
	signal.signal(signal.SIGINT, signal_handler)
	while True:
		for active_thread in active_threads:
			if not active_thread.isAlive():
				active_thread.join()
				active_threads.remove(active_thread)
		client_sock, address = server.accept()
		logger.log("accepted a request from client with address: " + str(address))
		user_accepted = False
		for user in config.accounting_users:
			if user[0] == address[0]:
				user_accepted = True
		if not user_accepted:
			client_sock.close()
			continue
		client_handler = threading.Thread(
			target=handle_request,
			args=(client_sock,client_sock,address[0])
		)
		client_handler.start()
		active_threads.append(client_handler)
	
def change_request(header, body):
	header.http_type = b'HTTP/1.0'
	if b'//' in header.address:
		header.address = header.address.split(b'//', 1)[1]
	if b'/' in header.address:
		header.address = b'/' + header.address.split(b'/', 1)[1]
	header.remove_header('Proxy-Connection')
	if config.privacy_enable:
		header.change_header('User-Agent', config.privacy_user_agent)
		
def inject_navbar(httpParser):
	if httpParser.index_content.split(b'\r\n\r\n').__len__() < 2:
		return
	header, html = httpParser.index_content.split(b'\r\n\r\n', 1)
	decompress = True
	try:
		html = zlib.decompress(httpParser.index_content, 16+zlib.MAX_WBITS)
	except:
		decompress = False
	navbar = BeautifulSoup("<div style=\"height:40px; background-color:rgb(18, 68, 68); direction: rtl; color: white; text-align: center; padding: 5px;\">" + config.injection_body + "</div>", features="html.parser")
	html = BeautifulSoup(html, features="html.parser")
	gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
	if not html.body == None:
		html.body.insert(0, navbar)
		html = html.encode('utf-8')
	else :
		html = httpParser.index_content.split(b'\r\n\r\n', 1)[1]
	if decompress:
		html = gzip_compress.compress(html.encode('utf-8')) + gzip_compress.flush()
	httpParser.index_content = header + b'\r\n\r\n' + html
	logger.log("html navbar injected")
	return html

def parse_html_date(date):
	date = date.decode("utf-8", errors='ignore')
	return datetime.datetime(*eut.parsedate(date)[:6]).timestamp()

def get_cached_data(cache_object, httpParser, context):
	final_data = b''
	if not cache_object.expire == None and int(parse_html_date(cache_object.expire)) > int(time.time()):
		final_data = cache_object.header + cache_object.data
	else:
		httpParser.httpreq.header.insert(-1, b'If-Modified-Since: ' + cache_object.get_date)
		host = httpParser.httpreq.get_value('Host').decode("utf-8", errors='ignore')
		modified_data = send_if_modified_since(httpParser, host, context)
		if not modified_data == None:
			final_data = modified_data
		else :
			final_data = cache_object.header + cache_object.data
	return final_data

def send_if_modified_since(httpParser, host, context):
	request_socket = socket(AF_INET, SOCK_STREAM)
	connection_addr = (host, 80)
	logger.log("proxy opening connection to server " + host + "...")
	request_socket.connect(connection_addr)
	logger.log("connection opened")
	httpParser.httpreq.change_method(b'HEAD')
	header = httpParser.httpreq.to_bytes()
	request_socket.send(header)
	logger.log("proxy sent if-modified-since request to server with headers:\n")
	logger.log_header(header)
	status_data = request_socket.recv(20)
	request_socket.close()
	if b'304' in status_data:
		return None
	else:
		request_socket = socket(AF_INET, SOCK_STREAM)
		connection_addr = (host, 80)
		logger.log("proxy opening connection to server " + host + "...")
		request_socket.connect(connection_addr)
		logger.log("connection opened")
		httpParser.httpreq.change_method(b'GET')
		httpParser.httpreq.remove_header("If-Modified-Since")
		header = httpParser.httpreq.to_bytes()
		request_socket.send(header)
		logger.log_header(header)
		ret = handle_response(request_socket, None, host, host, context, True)
		return ret

def handle_request(local_reader, local_writer, client_addr):
	httpParser = HttpParser()
	while not httpParser.is_complete:
		is_completed_before = httpParser.is_header_completed()
		if local_reader.fileno() == -1:
			return
		received = local_reader.recv(50)
		httpParser.add_data(received)
		if httpParser.is_header_completed() and not is_completed_before:
			logger.log("client sent request to proxy with headers:\n")
			logger.log_header(httpParser.httpreq)
			change_request(httpParser.httpreq, httpParser.data)

		if config.cache_enable and httpParser.is_header_completed():
			host = httpParser.httpreq.get_value('Host').decode("utf-8", errors='ignore')
			context = httpParser.httpreq.address.decode("utf-8", errors='ignore')
			found, cache_object = cache.find_and_get_data(host, context)
			if found:
				logger.log("cache: found " + host + context)
				final_data = get_cached_data(cache_object, httpParser, context)
				local_writer.send(final_data)
				return

		if not httpParser.httpreq == None:
			host_name = httpParser.httpreq.get_value('Host').decode("utf-8", errors='ignore')
			if restricted(host_name):
				local_writer.send(config.forbidden_page.encode("utf-8"))
				if restriction_notify(host_name):
					notification = b"ip address " + client_addr.encode("utf-8") + b" tried to send following request to " + host_name.encode("utf-8") + b"\n" + httpParser.httpreq.to_bytes() + httpParser.data
					send_mail_handler = threading.Thread(
						target=send_notification,
						args=(notification, )
					)
					send_mail_handler.start()
				local_reader.close()
				return

		if httpParser.is_header_completed() and not is_completed_before:
			httpParser.httpreq.change_header('Accept-Encoding', 'identity')
			send_request(httpParser.httpreq, httpParser.httpreq.to_bytes() + httpParser.data, local_writer, client_addr)
			logger.log_header(httpParser.httpreq)
		elif httpParser.is_header_completed():
			send_request(httpParser.httpreq, received, local_writer, client_addr)
	
	local_reader.close()

def handle_response(local_reader, local_writer, client_addr, host, context, if_modify=False):
	httpParser = HttpParser()
	received = b''
	local_reader.settimeout(2)
	while not httpParser.is_complete:
		is_completed_before = httpParser.is_header_completed()
		try:
			received = local_reader.recv(50)
		except:
			break
		client_used(client_addr, received.__len__())
		if not client_have_access(client_addr) and not if_modify:
			local_writer.send(config.forbidden_page.encode("utf-8"))
			if not if_modify:
				local_writer.close()
			local_reader.close()
			return
		
		if context == b'/' or context == b'/index.html' or context == b'/index.html#home' or if_modify:
			httpParser.index_content += received
		else:
			if not if_modify:
				local_writer.send(received)
		
		httpParser.add_data(received)

		if httpParser.is_header_completed() and not is_completed_before:
			logger.log("server sent response to proxy with headers:\n")
			logger.log_header(httpParser.httpresp)

	cache_object = None
	if(if_modify == False and config.cache_enable == True and not httpParser.httpresp == None):
		if not httpParser.httpresp.get_value("Pragma") == "no-cache":
			expire_date = httpParser.httpresp.get_value("Expires")
			now = datetime.datetime.now()
			stamp = mktime(now.timetuple())
			get_date = format_date_time(stamp).encode('utf-8')
			cache_object = CacheObject(host, context.decode("utf-8", errors='ignore'), expire_date, get_date, httpParser.data, httpParser.httpresp.to_bytes())
			cache.add_update_data(cache_object)
			logger.log("cache: added " + host + context.decode("utf-8", errors='ignore') + " cache-size: " + str(cache.data.__len__()))

	if config.injection_enable and (context == b'/' or context == b'/index.html' or context == b'/index.html#home'):
		html = inject_navbar(httpParser)
		if not if_modify:
			if not cache_object == None:
				cache_object.data = html
			local_writer.send(httpParser.index_content)
	if not if_modify:
		local_writer.close()
	else:
		return httpParser.index_content


def client_used(client_addr, byte_num):
	if not config.accounting_enable:
		return
	for user in config.accounting_users:
		if user[0] == client_addr:
			user[2] -= byte_num
			return

def client_have_access(client_addr):
	if not config.accounting_enable:
		return True
	for user in config.accounting_users:
		if user[0] == client_addr:
			return user[2] > 0
	return False

def restricted(host_name):
	if not config.restriction_enable:
		return False
	for target in config.restriction_targets:
		if target[0] == host_name:
			return True
	return False

def restriction_notify(host_name):
	if not config.restriction_enable:
		return False
	for target in config.restriction_targets:
		if target[0] == host_name:
			return target[1] == 'true'
	return False

def send_notification(message):
	send_notification_mail (config.admin_email.encode("utf-8"), message)
	logger.log ("restriction email sent")

def send_notification_mail(receiver, message):
	BUFFER_SIZE = 1024
	SMTP_PORT = 25
	mailserver = ("mail.ut.ac.ir", 25)
	mail_server_socket = socket(AF_INET, SOCK_STREAM)
	mail_server_socket.connect(mailserver)
	recv = mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"EHLO ut.ac.ir\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"AUTH LOGIN\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"YW1pLmFobWFkaQ==\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"QEFtaXJobWkxMjM=\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"MAIL FROM:<ami.ahmadi@ut.ac.ir>\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"RCPT TO:<" + receiver + b"@ut.ac.ir>\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"DATA\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"Subject: Proxy Notification\r\n\r\n" )
	mail_server_socket.send(message + b"\r\n.\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.send(b"QUIT\r\n")
	mail_server_socket.recv(BUFFER_SIZE)
	mail_server_socket.close()

def send_request(header, message, local_writer, client_addr):
	#request from browser for a server
	request_socket = socket(AF_INET, SOCK_STREAM)
	dest_addr = header.get_value('Host').decode("utf-8", errors='ignore')
	connection_addr = (dest_addr, 80)
	logger.log("proxy opening connection to server " + dest_addr + "...")
	request_socket.connect(connection_addr)
	logger.log("connection opened")
	request_socket.send(message)
	logger.log_header(header)
	handle_response(request_socket, local_writer, client_addr, dest_addr, header.address)

def shutdown_proxy(server):
	server.shutdown
	logger.log("proxy shutdown")

config = Config()
cache = Cache(config.cache_size)
logger = Logger(config.log_enable, config)
if __name__ == "__main__":
	main()