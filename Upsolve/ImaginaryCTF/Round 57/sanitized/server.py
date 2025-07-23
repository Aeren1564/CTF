#!/usr/local/bin/python3
import sqlite3
from flask import Flask, request
from os.path import exists
from secrets import token_urlsafe
from secret import FLAG

FILENAME = './database.db'

def run(cmd, commit=False):
	db = sqlite3.connect(FILENAME)
	cursor = db.cursor()
	try:
		res = cursor.execute(cmd).fetchall()
	except Exception:
		res = []
	if commit:
		db.commit()
	cursor.close()
	db.close()
	return res

if not exists(FILENAME):
	open(FILENAME, 'x')
	run("CREATE TABLE Users (username varchar(255), password varchar(255))", True)
	run(f"INSERT INTO Users (username, password) VALUES ('roo', '{token_urlsafe()}')", True)

def sanitize(string):
	return string.replace("'", "\\'").replace('"', '\\"')

app = Flask(__name__)

home_page = '''
<html>
<form action="/login" method="post">
	<label for="username">username</label><br>
	<input type="text" id="username" name="username"><br>
	<label for="password">password</label><br>
	<input type="text" id="password" name="password"><br>
	<input type="submit" value="login">
</form>
</html>
'''

@app.route("/", methods=["GET"])
def home():
	return home_page

@app.route("/login", methods=["POST"])
def login():
	username = sanitize(request.form.get('username'))
	password = sanitize(request.form.get('password'))
	if username and password:
		res = run(f"SELECT username, password FROM Users WHERE username='{username}' AND password='{password}';")
		if len(res) > 0 and res[0][0] == "roo":
			text = FLAG
		else:
			text = "who r u"
	else:
		text = "who r u"
	return f"<html>{text}</html>"

if __name__ == '__main__':
	app.run(port=8000, host="0.0.0.0")
