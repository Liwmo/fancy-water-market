import hmac
import hashlib
import random
import string

SECRET = 'D7q3JGdknW293N198afiy'
SALT_LEN = 8

def hash_str(s):
	return hmac.new(SECRET, str(s)).hexdigest()

def make_secure_val(user_id):
	return '%s|%s' % (user_id, hash_str(user_id))

def check_secure_val(secure_val):
	user_id = secure_val.split("|")[0]
	if make_secure_val(user_id) == secure_val:
		return secure_val

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(SALT_LEN))

def make_pwd_hash(username, pwd, salt = None):
	if not salt:
		salt = make_salt()
	pwd_hash = hashlib.sha256(username + pwd + salt).hexdigest()
	return str(pwd_hash) + "%s" % salt

def is_valid_pwd(name, pwd, pwd_hash):
	salt = pwd_hash[-SALT_LEN:]
	if make_pwd_hash(name, pwd, salt) == pwd_hash:
		return True
