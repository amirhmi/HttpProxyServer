class CacheObject:
	def __init__(self, host, context, expire, get_date, data, header):
		self.address = host + context
		self.header = header
		self.data = data
		self.expire = expire
		self.get_date = get_date

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