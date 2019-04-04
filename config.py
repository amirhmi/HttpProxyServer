import json

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
		json_obj = json.loads(content.decode("utf-8", errors='ignore'))
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