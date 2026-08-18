from fastapi import FastAPI,HTTPException,Request
from pydantic import BaseModel,Field
from .security import *
app=FastAPI(title="TrustGate");users={};audit=[];tokens=Tokens();guard=LoginGuard()
class Credentials(BaseModel):email:str=Field(max_length=254);password:str=Field(min_length=12,max_length=128)
@app.middleware("http")
async def headers(req:Request,call_next):
 response=await call_next(req);response.headers["X-Content-Type-Options"]="nosniff";response.headers["Cache-Control"]="no-store";return response
@app.post("/register",status_code=201)
def register(x:Credentials):
 key=x.email.lower()
 if key in users:raise HTTPException(409,"account unavailable")
 users[key]={"id":key,"role":"USER","password":hash_password(x.password)};audit.append({"action":"REGISTER","subject":key});return {"id":key,"role":"USER"}
@app.post("/login")
def login(x:Credentials):
 key=x.email.lower()
 if not guard.allowed(key):raise HTTPException(429,"temporarily locked")
 user=users.get(key)
 if not user or not verify_password(x.password,user["password"]):guard.fail(key);audit.append({"action":"LOGIN_FAILED","subject":key});raise HTTPException(401,"invalid credentials")
 audit.append({"action":"LOGIN_SUCCESS","subject":key});return {"access_token":tokens.access(user),"refresh_token":tokens.issue_refresh(key),"token_type":"bearer"}
class Refresh(BaseModel):token:str=Field(min_length=20,max_length=200)
@app.post("/refresh")
def refresh(x:Refresh):return {"refresh_token":tokens.rotate(x.token)}
