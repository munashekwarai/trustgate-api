import type { AuditEvent, RefreshSession, Store, User } from "./types.js";
export class MemoryStore implements Store {
 users=new Map<string,User>();refresh=new Map<string,RefreshSession>();audit:AuditEvent[]=[];
 async findUserByEmail(email:string){return [...this.users.values()].find(x=>x.email===email)??null}
 async findUserById(id:string){return this.users.get(id)??null}
 async createUser(user:User){if(await this.findUserByEmail(user.email))throw new Error("duplicate email");this.users.set(user.id,{...user})}
 async updateLoginState(id:string,failed:number,lockedUntil:Date|null){const user=this.users.get(id);if(!user)throw new Error("missing user");Object.assign(user,{failedAttempts:failed,lockedUntil})}
 async saveRefresh(session:RefreshSession){this.refresh.set(session.tokenHash,{...session})}
 async getRefresh(hash:string){return this.refresh.get(hash)??null}
 async consumeAndRotate(oldHash:string,replacement:RefreshSession,now:Date){const old=this.refresh.get(oldHash);if(!old||old.usedAt)return false;old.usedAt=now;this.refresh.set(replacement.tokenHash,replacement);return true}
 async revokeFamily(familyId:string,now:Date){for(const value of this.refresh.values())if(value.familyId===familyId)value.revokedAt=now}
 async addAudit(event:AuditEvent){this.audit.push({...event})}
 async listAudit(limit:number){return this.audit.slice(-limit).reverse()}
}
