import asyncio
import threading
from socket import *
import json
import time
import signal

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
						self.restriction_targets.append([target["IP"], target["volume"]])
		if "HTTPInjection" in json_obj:
			if "enable" in json_obj["HTTPInjection"]:
				self.injection_enable = json_obj["HTTPInjection"]["enable"]
			if "post" in json_obj["HTTPInjection"]:
				if "body" in json_obj["HTTPInjection"]["post"]:
					self.injection_body = json_obj["HTTPInjection"]["post"]["body"]
	
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
			if self.httpreq.method == b'HEAD':
				self.is_complete = True
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

# def handle_client(reader, writer):
# 	loop.create_task(handle_maintained_client(reader, writer, True))

def handle_maintained_client(local_reader, local_writer, is_reader):
	httpParser = HttpParser()
	while not httpParser.is_complete:
		if is_reader:
			is_completed_before = httpParser.is_header_completed()
			received = local_reader.recv(50)
			if httpParser.is_header_completed() and not is_completed_before:
				logger.log("client sent request to proxy with headers:\n" + httpParser.httpreq.to_str())
			httpParser.add_data(received)
			if httpParser.is_header_completed() and not is_completed_before:
				change_request(httpParser.httpreq, httpParser.data)
				send_request(httpParser.httpreq, httpParser.httpreq.to_bytes() + httpParser.data, local_writer)
				logger.log("proxy sent response to client with headers:\n" + httpParser.httpreq.to_str())
			elif httpParser.is_header_completed():
				send_request(httpParser.httpreq, received, local_writer)
		else:
			is_completed_before = httpParser.is_header_completed()
			received = local_reader.recv(50)
			local_writer.send(received)
			httpParser.add_data(received)
			if httpParser.is_header_completed() and not is_completed_before:
				logger.log("server sent response to proxy with headers:\n" + httpParser.httpresp.to_str())
	if not is_reader:
		local_writer.close()
	local_reader.close()


def send_request(header, message, local_writer):
	#request from browser for a server
	request_socket = socket(AF_INET, SOCK_STREAM)
	destination_ip = header.get_value('Host').decode("utf-8")
	connection_addr = (destination_ip, 80)
	logger.log("proxy opening connection to server " + destination_ip + "...")
	request_socket.connect(connection_addr)
	logger.log("connection opened")
	request_socket.send(message)
	logger.log("proxy sent request to server with headers:\n" + header.to_str())
	handle_maintained_client(request_socket, local_writer, False)

def shutdown_proxy(server):
	server.shutdown
	logger.log("proxy shutdown")

active_threads = []
config = Config()
logger = Logger(config.log_enable)
logger.log("proxy launched")
logger.log("creating server socket...")
server = socket(AF_INET, SOCK_STREAM)
logger.log("binding socket to port " + str(config.proxy_port) + "...")
server.bind((config.proxy_ip, config.proxy_port))
server.listen(8)
logger.log("listening to incoming requests...")
signal.signal(signal.SIGINT, shutdown_proxy)
while True:
	for active_thread in active_threads:
		if not active_thread.isAlive():
			active_thread.join()
			active_threads.remove(active_thread)
	client_sock, address = server.accept()
	logger.log("accepted a request from client")
	client_handler = threading.Thread(
        target=handle_maintained_client,
        args=(client_sock,client_sock,True)
    )
	client_handler.start()
	active_threads.append(client_handler)