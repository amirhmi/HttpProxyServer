import asyncio
import threading
from socket import *

class Config:
	def __init__(self):
		self.proxy_port = 8888
		self.proxy_ip = '127.0.0.1'
		self.user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'
		self.socket_limit = 20

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
				self.header.remove(i)
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

	def add_data(self, data_part):
		self.data += data_part
		if self.is_header_completed():
			if self.data.__len__() >= self.content_length:
				self.is_complete = True
			return
		while b'\r\n' in self.data:
			splited = self.data.split(b'\r\n', 1)
			self.parts.append(splited[0])
			self.data = splited[1]
			if self.is_header_completed():
				self.decodeHeader()
		if self.is_header_completed():
			if self.data.__len__() >= self.content_length:
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
	header.address = b'/' + header.address.split(b'/', 1)[1]
	header.remove_header('Proxy-Connection')
	header.change_header('User-Agent', config.user_agent)

# def handle_client(reader, writer):
# 	loop.create_task(handle_maintained_client(reader, writer, True))

def handle_maintained_client(local_reader, local_writer, is_reader):
	httpParser = HttpParser()
	while not httpParser.is_complete:
		if is_reader:
			is_completed_before = httpParser.is_header_completed()
			received = local_reader.recv(10000)
			httpParser.add_data(received)
			if httpParser.is_header_completed() and not is_completed_before:
				change_request(httpParser.httpreq, httpParser.data)
				send_request(httpParser.httpreq, httpParser.httpreq.to_bytes() + httpParser.data, local_writer)
			elif httpParser.is_header_completed():
				send_request(httpParser.httpreq, received, local_writer)
		else:
			received = local_reader.recv(10000)
			local_writer.send(received)
			if received.__len__() == 0:
				continue
			httpParser.add_data(received)
	if not is_reader:
		local_writer.close()
	#local_reader.close()


def send_request(header, message, local_writer):
	#request from browser for a server
	request_socket = socket(AF_INET, SOCK_STREAM)
	connection_addr = (header.get_value('Host').decode("utf-8"), 80)
	request_socket.connect(connection_addr)
	request_socket.send(message)
	handle_maintained_client(request_socket, local_writer, False)

def handle_response(header, body, local_writer):
	local_writer.write(header.to_bytes() + body)
	local_writer.close()

#active_threads = []
config = Config()
server = socket(AF_INET, SOCK_STREAM)
server.bind((config.proxy_ip, config.proxy_port))
server.listen(100)
while True:
	#for i in range(active_threads.__len__()):
	#	if not active_threads[i].isAlive():
	#		active_threads[i].join()
	#		active_threads.remove(i)
	#		i -= 1
	client_sock, address = server.accept()
	client_handler = threading.Thread(
        target=handle_maintained_client,
        args=(client_sock,client_sock,True)
    )
	client_handler.start()
	#active_threads.append(client_handler)