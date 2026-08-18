import base64,hashlib,hmac,json,os,secrets,time
ROLES={"ADMIN":{"read:any","write:any","audit:read"},"MANAGER":{"read:any","write:own"},"USER":{"read:own","write:own"},"AUDITOR":{"audit:read"}}
def hash_password(password,salt=None):
 if len(password)<12:raise ValueError("password must contain at least 12 characters")
 salt=salt or os.urandom(16);digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1);return base64.urlsafe_b64encode(salt+digest).decode()
def verify_password(password,encoded):
 raw=base64.urlsafe_b64decode(encoded);return hmac.compare_digest(hash_password(password,raw[:16]),encoded)
def authorize(actor,permission,owner=None):return permission in ROLES[actor["role"]] or (permission.endswith(":own") and actor["id"]==owner)
class Tokens:
 def __init__(self,secret=None):self.secret=secret or secrets.token_bytes(32);self.refresh={}
 def access(self,user,ttl=900):
  body=base64.urlsafe_b64encode(json.dumps({"sub":user["id"],"role":user["role"],"exp":int(time.time())+ttl}).encode()).decode();sig=hmac.new(self.secret,body.encode(),hashlib.sha256).hexdigest();return body+"."+sig
 def decode(self,token):
  body,sig=token.rsplit(".",1)
  if not hmac.compare_digest(sig,hmac.new(self.secret,body.encode(),hashlib.sha256).hexdigest()):raise ValueError("invalid token")
  claims=json.loads(base64.urlsafe_b64decode(body));
  if claims["exp"]<time.time():raise ValueError("expired token")
  return claims
 def issue_refresh(self,user_id):
  raw=secrets.token_urlsafe(32);self.refresh[hashlib.sha256(raw.encode()).hexdigest()]={"user_id":user_id,"used":False};return raw
 def rotate(self,raw):
  key=hashlib.sha256(raw.encode()).hexdigest();row=self.refresh.get(key)
  if not row or row["used"]:raise ValueError("refresh token invalid or replayed")
  row["used"]=True;return self.issue_refresh(row["user_id"])
class LoginGuard:
 def __init__(self,limit=5,lock_seconds=300):self.limit=limit;self.lock_seconds=lock_seconds;self.failures={}
 def allowed(self,key,now=None):
  now=now or time.time();xs=[x for x in self.failures.get(key,[]) if x>now-self.lock_seconds];self.failures[key]=xs;return len(xs)<self.limit
 def fail(self,key,now=None):self.failures.setdefault(key,[]).append(now or time.time())
