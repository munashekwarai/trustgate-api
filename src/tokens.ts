import { createHash, randomBytes, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import type { Principal, Role } from "./domain.js";
import type { RefreshSession, Store, User } from "./types.js";

export class TokenService {
  private readonly key:Uint8Array;
  constructor(secret:string,private readonly issuer="trustgate",private readonly audience="trustgate-api") {
    if (Buffer.byteLength(secret)<32) throw new Error("TOKEN_SECRET must be at least 32 bytes"); this.key=new TextEncoder().encode(secret);
  }
  async access(user:User,ttlSeconds=900):Promise<string> {
    return new SignJWT({role:user.role}).setProtectedHeader({alg:"HS256",typ:"JWT"}).setSubject(user.id)
      .setJti(randomUUID()).setIssuer(this.issuer).setAudience(this.audience).setIssuedAt().setExpirationTime(`${ttlSeconds}s`).sign(this.key);
  }
  async verify(token:string):Promise<Principal> {
    const {payload}=await jwtVerify(token,this.key,{issuer:this.issuer,audience:this.audience,algorithms:["HS256"]});
    if (!payload.sub || !payload.jti || !["ADMIN","MANAGER","USER","AUDITOR"].includes(String(payload.role))) throw new Error("invalid access claims");
    return {id:payload.sub,tokenId:payload.jti,role:payload.role as Role};
  }
  newRefresh(userId:string,familyId:string=randomUUID(),now=new Date()):{raw:string;session:RefreshSession} {
    const raw=randomBytes(32).toString("base64url");
    return {raw,session:{tokenHash:this.hash(raw),familyId,userId,expiresAt:new Date(now.getTime()+30*86400_000),usedAt:null,revokedAt:null}};
  }
  hash(raw:string):string{return createHash("sha256").update(raw).digest("hex")}
  async rotate(raw:string,store:Store,now=new Date()):Promise<{raw:string;userId:string}> {
    const oldHash=this.hash(raw);const current=await store.getRefresh(oldHash);
    if (!current || current.revokedAt || current.expiresAt<=now) throw new Error("refresh token invalid or expired");
    if (current.usedAt) {await store.revokeFamily(current.familyId,now);throw new Error("refresh token replay detected");}
    const next=this.newRefresh(current.userId,current.familyId,now);
    if (!await store.consumeAndRotate(oldHash,next.session,now)) throw new Error("refresh token rotation conflict");
    return {raw:next.raw,userId:current.userId};
  }
}
