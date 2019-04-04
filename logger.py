import logging
import threading
import time

class Logger:
	def __init__(self, enable, config):
		self.enable = enable
		self.config = config
		logging.basicConfig(filename=self.config.log_file, level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
		self.sem = threading.Semaphore()

	def log(self, message):
		if not self.enable:
			return
		try:
			self.sem.acquire()
			logging.info(message)
			self.sem.release()
		except:
			self.sem.release()

	def log_header(self, header):
		if not self.enable:
			return
		try:
			message = 'proxy sent response to client with headers:\n-----------------------------------------\n' + header.to_str() + '-----------------------------------------'
			self.sem.acquire()			
			logging.info(message)
			self.sem.release()
		except:
			self.sem.release()
