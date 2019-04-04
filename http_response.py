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
			if line.split(b':')[0].decode("utf-8", errors='ignore').strip() == key:
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
		ret += self.http_type.decode("utf-8", errors='ignore') + ' '
		ret += self.status_code.decode("utf-8", errors='ignore') + ' '
		ret += self.status.decode("utf-8", errors='ignore')
		ret += '\n'
		for line in self.header:
			ret += line.decode("utf-8", errors='ignore') + '\n'
		return ret