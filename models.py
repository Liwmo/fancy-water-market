from google.appengine.ext import db

class Inventory(db.Model):
	photo = db.LinkProperty(required = True)
	name = db.TextProperty(required = True)
	price = db.FloatProperty(required = True)

class User(db.Model):
	username = db.StringProperty(required = True)
	pwd_hash = db.TextProperty(required = True)