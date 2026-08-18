import { randomUUID } from "node:crypto";
import { AppError, type Role } from "./domain.js";
import { hashPassword, verifyPassword } from "./password.js";
import { TokenService } from "./tokens.js";
import type { Store, User } from "./types.js";
export class AuthService {
 constructor(private store:Store,private tokens:TokenService,private maxFailures=5,private lockMs=15*60_000){}
 private audit(action:string,subjectId:string|null,sourceIp:string,outcome:"SUCCESS"|"DENIED",metadata:Record<string,unknown>={}){return this.store.addAudit({actorId:subjectId,action,subjectId,sourceIp,outcome,metadata,createdAt:new Date()})}
 async register(email:string,password:string,sourceIp:string,role:Role="USER"){
  const normalized=email.trim().toLowerCase();if(await this.store.findUserByEmail(normalized))throw new AppError("ACCOUNT_UNAVAILABLE",409,"account unavailable");
  const user:User={id:randomUUID(),email:normalized,passwordHash:await hashPassword(password),role,failedAttempts:0,lockedUntil:null,createdAt:new Date()};
  await this.store.createUser(user);await this.audit("USER_REGISTERED",user.id,sourceIp,"SUCCESS");return {id:user.id,email:user.email,role:user.role};
 }
 async login(email:string,password:string,sourceIp:string,now=new Date()){
  const user=await this.store.findUserByEmail(email.trim().toLowerCase());
  if(user?.lockedUntil&&user.lockedUntil>now){await this.audit("LOGIN_LOCKED",user.id,sourceIp,"DENIED");throw new AppError("ACCOUNT_LOCKED",429,"account temporarily locked")}
  const valid=user?await verifyPassword(password,user.passwordHash):await verifyPassword(password,"scrypt$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  if(!user||!valid){if(user){const failed=user.failedAttempts+1;await this.store.updateLoginState(user.id,failed,failed>=this.maxFailures?new Date(now.getTime()+this.lockMs):null)}await this.audit("LOGIN_FAILED",user?.id??null,sourceIp,"DENIED");throw new AppError("INVALID_CREDENTIALS",401,"invalid credentials")}
  await this.store.updateLoginState(user.id,0,null);const refresh=this.tokens.newRefresh(user.id,undefined,now);await this.store.saveRefresh(refresh.session);await this.audit("LOGIN_SUCCEEDED",user.id,sourceIp,"SUCCESS");
  return {accessToken:await this.tokens.access(user),refreshToken:refresh.raw,tokenType:"Bearer",expiresIn:900};
 }
 async refresh(raw:string,sourceIp:string,now=new Date()){
  try{const rotated=await this.tokens.rotate(raw,this.store,now);const user=await this.store.findUserById(rotated.userId);if(!user)throw new Error("user missing");await this.audit("TOKEN_REFRESHED",user.id,sourceIp,"SUCCESS");return {accessToken:await this.tokens.access(user),refreshToken:rotated.raw,tokenType:"Bearer",expiresIn:900}}
  catch{await this.audit("TOKEN_REFRESH_DENIED",null,sourceIp,"DENIED");throw new AppError("INVALID_REFRESH_TOKEN",401,"refresh token invalid")}
 }
}
