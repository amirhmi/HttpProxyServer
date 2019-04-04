import time

class Logger:
	def __init__(self, enable, config):
		self.enable = enable
		self.config = config

	def log(self, message):
		if not self.enable:
			return
		try:
			with open(self.config.log_file, 'a+') as f:
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
			with open(self.config.log_file, 'a+') as f:
				f.write('-----------------------------------------\n')
				f.write(header.to_str())
				f.write('-----------------------------------------\n')
				f.write('\n')
		except:
			print("cannot write logs to file!")
