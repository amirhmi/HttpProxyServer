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
			if line.split(b':')[0].decode("utf-8", errors='ignore').strip() == key:
				return line.split(b' ', 1)[1]
		return None
	
	def remove_header (self, key):
		for i in range(self.header.__len__()):
			line = self.header[i]
			if line.split(b':')[0].decode("utf-8", errors='ignore').strip() == key:
				self.header.remove(line)
				return
	
	def change_header (self, key, value):
		for i in range(self.header.__len__()):
			line = self.header[i]
			if line.split(b':')[0].decode("utf-8", errors='ignore').strip() == key:
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
		ret += self.method.decode("utf-8", errors='ignore') + ' '
		ret += self.address.decode("utf-8", errors='ignore') + ' '
		ret += self.http_type.decode("utf-8", errors='ignore')
		ret += '\n'
		for line in self.header:
			ret += line.decode("utf-8", errors='ignore') + '\n'
		return ret