#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import re, math
import hashutils
from google.appengine.ext import db
from models import Inventory, User
import urllib2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def has_valid_cookie(self, *a, **kw):
	cookie_hash = self.request.cookies.get('user')
	if cookie_hash and hashutils.check_secure_val(cookie_hash):
		return True
	return False

def user_required(handler):
	def check_login(self, *a, **kw):
		if has_valid_cookie(self, *a, **kw):
			return handler(self, *a, **kw)
		else:
			self.redirect('/login')
	return check_login

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainHandler(Handler):
	@user_required
	def get(self):
		products = Inventory.all()
		filtered_product = products.order("price")
		self.render("main.html", products = filtered_product)

	def post(self):
		total = 0
		products = db.GqlQuery("SELECT * FROM Inventory")
		for product in products:
			quantity = self.request.get(product.name)
			total += float(quantity) * product.price
		self.redirect("/confirm?total=" + str(total))

class LoginHandler(Handler):
	def get(self):
		# pwd_hash = hashutils.make_pwd_hash("test", "password")
		# user = User(username = "test", pwd_hash=pwd_hash)
		# user.put()
		# Inventory(name="Creed Silver Mountain Water", price=515.00, photo="https://www.google.com/aclk?sa=l&ai=DChcSEwj74fiaxpXSAhUeSw0KHZJ9Be4YABABGgJxYg&sig=AOD64_0q4OYm_yYDvcyVji56alDwobTjcA&ctype=5&q=&ved=0ahUKEwiazPSaxpXSAhXMlVQKHVfVB50QwjwIBQ&adurl=").put()
		# Inventory(name="Creed Virgin Island Water", price=395.00, photo="https://www.google.com/aclk?sa=l&ai=DChcSEwj74fiaxpXSAhUeSw0KHZJ9Be4YABAHGgJxYg&sig=AOD64_0uyZ1dGL-3Nc7LhfDg5i2Ksehe8Q&ctype=5&q=&ved=0ahUKEwiazPSaxpXSAhXMlVQKHVfVB50QwjwIKw&adurl=").put()
		# Inventory(name="Essentia Alkaline Water", price=21.99, photo="https://www.google.com/aclk?sa=l&ai=DChcSEwj74fiaxpXSAhUeSw0KHZJ9Be4YABAbGgJxYg&sig=AOD64_1gK3_hk6VYecKiR-adj6Xs7lD0MQ&ctype=5&q=&ved=0ahUKEwiazPSaxpXSAhXMlVQKHVfVB50QqCsIqAE&adurl=").put()

		error = ""
		self.render("login.html", error = error)

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		user_query = db.GqlQuery("SELECT * FROM User WHERE username = '%s'" % username)
		user = user_query.get()

		if user and hashutils.is_valid_pwd(username, password, user.pwd_hash):
			cookie_hash = hashutils.make_secure_val(user.key().id())
			self.response.headers.add_header('Set-Cookie', 'user=%s; path=/' % cookie_hash)
			self.redirect('/')
		else:
			error = "Invalid credentials."
			self.render("login.html", error = error)

class ConfirmationHandler(Handler):
	def get(self):
		total = self.request.get("total")
		self.render("confirm.html", total = total)

class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user=; path=/')
		self.redirect('/login')

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/login', LoginHandler),
    ('/confirm', ConfirmationHandler),
    ('/logout', LogoutHandler)
], debug=True)
