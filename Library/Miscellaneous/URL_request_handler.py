class URL_request_handler:
	import requests
	def __init__(self, base_url: str):
		assert base_url.startswith("http") and base_url.endswith("/")
		self.session = self.requests.Session()
		self.base_url = base_url[:]
	def get(self, url_args: list):
		return self.session.get(self.base_url + "/".join(url_args), verify = False).json()
	def post(self, url_args: list, data):
		return self.session.post(self.base_url + "/".join(url_args), data = data, verify = False)
