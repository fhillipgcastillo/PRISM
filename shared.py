import base64

def descriptBase64Content(content):
	try:
		return base64.b64decode(content)
	except:
		return content