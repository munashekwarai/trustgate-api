from app.security import *
def test_password_and_authorization():
 h=hash_password("correct horse battery staple");assert verify_password("correct horse battery staple",h);assert authorize({"id":"u1","role":"ADMIN"},"read:any")
def test_refresh_rotation_rejects_replay():
 t=Tokens(b"x"*32);r=t.issue_refresh("u");assert t.rotate(r)
 try:t.rotate(r)
 except ValueError:pass
 else:raise AssertionError("replay accepted")
def test_lockout():
 g=LoginGuard(limit=2);g.fail("x",1);g.fail("x",2);assert not g.allowed("x",3)
