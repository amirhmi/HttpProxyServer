from http_request import HttpRequestHeaderData
from http_response import HttpResponsetHeaderData

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