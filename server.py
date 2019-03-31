import asyncio
import threading
from socket import *
import json
import signal
import sys
import zlib
import datetime
import time
from time import mktime
from wsgiref.handlers import format_date_time
import email.utils as eut
from bs4 import BeautifulSoup
import base64

class Config:
	def __init__(self):
		self.proxy_port = 8888
		self.proxy_ip = '127.0.0.1'
		self.privacy_enable = False
		self.privacy_user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'
		self.log_enable = False
		self.log_file = ""
		self.cache_enable = False
		self.cache_size = 0
		self.restriction_enable = False
		self.restriction_targets = []
		self.accounting_enable = False
		self.accounting_users = []
		self.injection_enable = False
		self.injection_body = ''
		self.admin_email = "ami.ahmadi"
		self.forbidden_page = ""
		self.read_config()
	
	def read_config(self):
		try:
			with open("config.json", "rb") as f:
				content = f.read()
		except:
			return
		json_obj = json.loads(content.decode("utf-8"))
		if "port" in json_obj:
			self.proxy_port = json_obj["port"]
		if "logging" in json_obj:
			if "enable" in json_obj["logging"]:
				self.log_enable = json_obj["logging"]["enable"]
			if "logFile" in json_obj["logging"]:
				self.log_file = json_obj["logging"]["logFile"]
		if "caching" in json_obj:
			if "enable" in json_obj["caching"]:
				self.cache_enable = json_obj["caching"]["enable"]
			if "size" in json_obj["caching"]:
				self.cache_size = json_obj["caching"]["size"]
		if "privacy" in json_obj:
			if "enable" in json_obj["privacy"]:
				self.privacy_enable = json_obj["privacy"]["enable"]
			if "userAgent" in json_obj["privacy"]:
				self.privacy_user_agent = json_obj["privacy"]["userAgent"]
		if "restriction" in json_obj:
			if "enable" in json_obj["restriction"]:
				self.restriction_enable = json_obj["restriction"]["enable"]
			if "targets" in json_obj["restriction"]:
				targets = json_obj["restriction"]["targets"]
				for target in targets:
					if "URL" in target and "notify" in target:
						self.restriction_targets.append([target["URL"], target["notify"]])
					elif "URL" in target:
						self.restriction_targets.append([target["URL"], False])
		if "accounting" in json_obj:
			if "enable" in json_obj["accounting"]:
				self.accounting_enable = json_obj["accounting"]["enable"]
			if "users" in json_obj["accounting"]:
				targets = json_obj["accounting"]["users"]
				for target in targets:
					if "IP" in target and "volume" in target:
						self.accounting_users.append([target["IP"], target["volume"], int(target["volume"])])
		if "HTTPInjection" in json_obj:
			if "enable" in json_obj["HTTPInjection"]:
				self.injection_enable = json_obj["HTTPInjection"]["enable"]
			if "post" in json_obj["HTTPInjection"]:
				if "body" in json_obj["HTTPInjection"]["post"]:
					self.injection_body = json_obj["HTTPInjection"]["post"]["body"]
		if "ForbiddenPage" in json_obj:
			self.forbidden_page = json_obj["ForbiddenPage"]
	
class Logger:
	def __init__(self, enable):
		self.enable = enable
	
	def log(self, message):
		if not self.enable:
			return
		try:
			with open(config.log_file, 'a+') as f:
				f.write('[')
				f.write(time.asctime(time.localtime(time.time())))
				f.write(']')
				f.write(message)
				f.write('\n')
		except:
			print("cannot write logs to file!")
	
	def log_header(self, header):
		if not self.enable:
			return
		try:
			with open(config.log_file, 'a+') as f:
				f.write('-----------------------------------------\n')
				f.write(header.to_str())
				f.write('-----------------------------------------\n')
				f.write('\n')
		except:
			print("cannot write logs to file!")

class HttpRequestHeaderData:
	def __init__(self, header):
		self.method = b''
		self.address = b''
		self.http_type = b''
		self.corrupt = True
		self.header = header
		self.parse()
	
	def parse(self):
		splited = self.header[0].split(b' ')
		if not splited.__len__() == 3:
			return
		self.method, self.address, self.http_type = splited
		self.corrupt = False
		self.header = self.header[1:]
	
	def get_value (self, key):
		for line in self.header:
			if line.split(b':')[0].decode("utf-8").strip() == key:
				return line.split(b' ', 1)[1]
		return None
	
	def remove_header (self, key):
		for i in range(self.header.__len__()):
			line = self.header[i]
			if line.split(b':')[0].decode("utf-8").strip() == key:
				self.header.remove(line)
				return
	
	def change_header (self, key, value):
		for i in range(self.header.__len__()):
			line = self.header[i]
			if line.split(b':')[0].decode("utf-8").strip() == key:
				self.header[i] = key.encode("utf-8") + b': ' + value.encode("utf-8")
				return
	
	def to_bytes(self):
		ret = b''
		ret += self.method + b' '
		ret += self.address + b' '
		ret += self.http_type
		ret += b'\r\n'
		for line in self.header:
			ret += line + b'\r\n'
		return ret

	def change_method(self, method):
		self.method = method

	def to_str(self):
		ret = ''
		ret += self.method.decode("utf-8") + ' '
		ret += self.address.decode("utf-8") + ' '
		ret += self.http_type.decode("utf-8")
		ret += '\n'
		for line in self.header:
			ret += line.decode("utf-8") + '\n'
		return ret

class HttpResponsetHeaderData:
	def __init__(self, header):
		self.http_type = b''
		self.status_code = b''
		self.status = b''
		self.corrupt = True
		self.header = header
		self.parse()

	def parse(self):
		splited = self.header[0].split(b' ')
		if not splited.__len__ == 3:
			return
		self.http_type, self.status_code, self.status = splited
		self.corrupt = False
		self.header = self.header[1:]
	
	def get_value (self, key):
		for line in self.header:
			if line.split(b':')[0].decode("utf-8").strip() == key:
				return line.split(b' ', 1)[1]
		return None
	
	def to_bytes(self):
		ret = b''
		ret += self.http_type + b' '
		ret += self.status_code + b' '
		ret += self.status
		ret += b'\r\n'
		for line in self.header:
			ret += line + b'\r\n'
		return ret
	
	def to_str(self):
		ret = ''
		ret += self.http_type.decode("utf-8") + ' '
		ret += self.status_code.decode("utf-8") + ' '
		ret += self.status.decode("utf-8")
		ret += '\n'
		for line in self.header:
			ret += line.decode("utf-8") + '\n'
		return ret

class CacheObject:
	def __init__(self, host, context, expire, get_date, data, header):
		self.address = host + context
		self.header = header
		self.data = data
		self.expire = expire
		self.get_date = get_date
	
	def get_cached_data(self, data):
		pass

class Cache:
	def __init__(self, max):
		self.data = []
		self.max = max
	
	def is_full(self):
		return data.__len__() >= self.max
	
	def add_update_data(self, data):
		for d in self.data:
			if d.address == data.address:
				self.data.remove(d)
		if self.data.__len__() < self.max:
			self.data.append(data)
		else:
			self.data.pop(0)
			self.data.append(data)
	
	def find_and_get_data(self, host, context):
		address = host + context
		for d in self.data:
			if d.address == address:
				self.data.remove(d)
				self.data.append(d)
				return True, d
		return False, None
	

class HttpParser:
	def __init__(self):
		self.data = b''
		self.parts = []
		self.is_request = False
		self.accepted_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'OPTIONS', b'HEAD', b'CONNECT', b'TRACE', b'PATCH']
		self.httpreq = None
		self.httpresp = None
		self.content_length = 0
		self.is_complete = False
		self.empty_num = 0
		self.index_content = b''

	def add_data(self, data_part):
		self.data += data_part
		if data_part.__len__() == 0:
			self.empty_num += 1
		self.check_complition(data_part)	
		if self.is_header_completed():
			return
		while b'\r\n' in self.data:
			splited = self.data.split(b'\r\n', 1)
			self.parts.append(splited[0])
			self.data = splited[1]
			if self.is_header_completed():
				self.decodeHeader()
		self.check_complition(data_part)

	def check_complition(self, last_part):
		if self.empty_num > 300:
			self.is_complete = True
			return
		if self.is_header_completed():
			if last_part.__len__() == 0 and not self.is_request:
				self.is_complete = True
			elif self.content_length > 0 and self.data.__len__() >= self.content_length:
				self.is_complete = True

	def is_header_completed(self):
		for part in self.parts:
			if part.__len__() == 0:
				return True
		return False

	def decodeHeader(self):
		if self.parts[0].split(b' ')[0] in self.accepted_methods:
			self.is_request = True
			self.httpreq = HttpRequestHeaderData(self.parts)
			self.content_length = self.httpreq.get_value("Content-Length")
		else:
			self.httpresp = HttpResponsetHeaderData(self.parts)
			self.content_length = self.httpresp.get_value("Content-Length")
		if self.content_length == None:
			self.content_length = 0
		else:
			self.content_length = int(self.content_length)
	
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

def parse_html_date(date):
	date = date.decode('utf-8')
	return datetime.datetime(*eut.parsedate(date)[:6]).timestamp()

def get_cached_data(cache_object, httpParser, context):
	final_data = b''
	if not cache_object.expire == None and int(parse_html_date(cache_object.expire)) > int(time.time()):
		final_data = cache_object.header + cache_object.data
	else:
		httpParser.httpreq.header.insert(-1, b'If-Modified-Since: ' + cache_object.get_date)
		host = httpParser.httpreq.get_value('Host').decode("utf-8")
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
		logger.log("proxy sent request to server with headers:\n")
		logger.log_header(header)
		ret = handle_response(request_socket, None, host, host, context, True)
		return ret

def handle_request(local_reader, local_writer, client_addr):
	httpParser = HttpParser()
	while not httpParser.is_complete:
		is_completed_before = httpParser.is_header_completed()
		received = local_reader.recv(50)
		httpParser.add_data(received)
		if httpParser.is_header_completed() and not is_completed_before:
			logger.log("client sent request to proxy with headers:\n")
			logger.log_header(httpParser.httpreq)
			change_request(httpParser.httpreq, httpParser.data)

		if config.cache_enable and httpParser.is_header_completed():
			host = httpParser.httpreq.get_value('Host').decode("utf-8")
			context = httpParser.httpreq.address.decode("utf-8")
			found, cache_object = cache.find_and_get_data(host, context)
			if found:
				print("found " + host + " " + context)
				final_data = get_cached_data(cache_object, httpParser, context)
				local_writer.send(final_data)
				return

		if not httpParser.httpreq == None:
			host_name = httpParser.httpreq.get_value('Host').decode("utf-8")
			if restricted(host_name):
				local_writer.send(config.forbidden_page.encode("utf-8"))
				if restriction_notify(host_name):
					send_notification(b"ip address " + client_addr.encode("utf-8") + b" tried to send following request to " + host_name.encode("utf-8") + b"\n" + httpParser.httpreq.to_bytes() + httpParser.data)
				local_reader.close()
				return

		if httpParser.is_header_completed() and not is_completed_before:
			send_request(httpParser.httpreq, httpParser.httpreq.to_bytes() + httpParser.data, local_writer, client_addr)
			logger.log("proxy sent response to client with headers:\n")
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

	if(if_modify == False and config.cache_enable == True and not httpParser.httpresp == None):
		if not httpParser.httpresp.get_value("Pragma") == "no-cache":
			expire_date = httpParser.httpresp.get_value("Expires")
			now = datetime.datetime.now()
			stamp = mktime(now.timetuple())
			get_date = format_date_time(stamp).encode('utf-8')
			cache_object = CacheObject(host, context.decode("utf-8"), expire_date, get_date, httpParser.data, httpParser.httpresp.to_bytes())
			cache.add_update_data(cache_object)
			print("added " + host + " " + context.decode("utf-8") + " " + str(cache.data.__len__()))

	if config.injection_enable and (context == b'/' or context == b'/index.html' or context == b'/index.html#home'):
		inject_navbar(httpParser)
		if not if_modify:
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
	print ("restriction email sent")
	send_notification_mail (config.admin_email.encode("utf-8"), message)

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
	dest_addr = header.get_value('Host').decode("utf-8")
	connection_addr = (dest_addr, 80)
	logger.log("proxy opening connection to server " + dest_addr + "...")
	request_socket.connect(connection_addr)
	logger.log("connection opened")
	request_socket.send(message)
	logger.log("proxy sent request to server with headers:\n")
	logger.log_header(header)
	handle_response(request_socket, local_writer, client_addr, dest_addr, header.address)

def shutdown_proxy(server):
	server.shutdown
	logger.log("proxy shutdown")

active_threads = []
config = Config()
cache = Cache(config.cache_size)
logger = Logger(config.log_enable)
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