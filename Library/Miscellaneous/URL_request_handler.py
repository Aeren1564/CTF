class URL_request_handler:
	import requests
	def __init__(self, base_url: str):
		assert base_url.startswith("http") and base_url.endswith("/")
		self.session = self.requests.Session()
		self.base_url = base_url
	def get(self, *args):
		return self.session.get(self.base_url + "/".join(args) + "/", verify = False).json()
