import { Pool, type PoolClient } from "pg";
import type { AuditEvent, RefreshSession, Store, User } from "./types.js";
export class PostgresStore implements Store {
 constructor(private readonly pool:Pool){}
 private user(row:any):User{return {id:row.id,email:row.email,passwordHash:row.password_hash,role:row.role,failedAttempts:row.failed_attempts,lockedUntil:row.locked_until,createdAt:row.created_at}}
 async findUserByEmail(email:string){const r=await this.pool.query("SELECT * FROM users WHERE email=$1",[email]);return r.rowCount?this.user(r.rows[0]):null}
 async findUserById(id:string){const r=await this.pool.query("SELECT * FROM users WHERE id=$1",[id]);return r.rowCount?this.user(r.rows[0]):null}
 async createUser(u:User){await this.pool.query("INSERT INTO users(id,email,password_hash,role,failed_attempts,locked_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",[u.id,u.email,u.passwordHash,u.role,u.failedAttempts,u.lockedUntil,u.createdAt])}
 async updateLoginState(id:string,f:number,l:Date|null){await this.pool.query("UPDATE users SET failed_attempts=$2,locked_until=$3 WHERE id=$1",[id,f,l])}
 async saveRefresh(s:RefreshSession){await this.pool.query("INSERT INTO refresh_sessions(token_hash,family_id,user_id,expires_at) VALUES($1,$2,$3,$4)",[s.tokenHash,s.familyId,s.userId,s.expiresAt])}
 async getRefresh(hash:string){const r=await this.pool.query("SELECT * FROM refresh_sessions WHERE token_hash=$1",[hash]);if(!r.rowCount)return null;const x=r.rows[0];return {tokenHash:x.token_hash,familyId:x.family_id,userId:x.user_id,expiresAt:x.expires_at,usedAt:x.used_at,revokedAt:x.revoked_at}}
 async consumeAndRotate(hash:string,s:RefreshSession,now:Date){const c=await this.pool.connect();try{await c.query("BEGIN");const r=await c.query("UPDATE refresh_sessions SET used_at=$2 WHERE token_hash=$1 AND used_at IS NULL AND revoked_at IS NULL",[hash,now]);if(r.rowCount!==1){await c.query("ROLLBACK");return false}await c.query("INSERT INTO refresh_sessions(token_hash,family_id,user_id,expires_at) VALUES($1,$2,$3,$4)",[s.tokenHash,s.familyId,s.userId,s.expiresAt]);await c.query("COMMIT");return true}catch(e){await c.query("ROLLBACK");throw e}finally{c.release()}}
 async revokeFamily(id:string,now:Date){await this.pool.query("UPDATE refresh_sessions SET revoked_at=$2 WHERE family_id=$1 AND revoked_at IS NULL",[id,now])}
 async addAudit(e:AuditEvent){await this.pool.query("INSERT INTO audit_events(actor_id,action,subject_id,source_ip,outcome,metadata,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)",[e.actorId,e.action,e.subjectId,e.sourceIp,e.outcome,e.metadata,e.createdAt])}
 async listAudit(limit:number){const r=await this.pool.query("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT $1",[limit]);return r.rows.map(x=>({id:x.id,actorId:x.actor_id,action:x.action,subjectId:x.subject_id,sourceIp:x.source_ip,outcome:x.outcome,metadata:x.metadata,createdAt:x.created_at}))}
}
