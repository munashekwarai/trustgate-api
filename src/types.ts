import type { Role } from "./domain.js";
export interface User { id:string; email:string; passwordHash:string; role:Role; failedAttempts:number; lockedUntil:Date|null; createdAt:Date }
export interface RefreshSession { tokenHash:string; familyId:string; userId:string; expiresAt:Date; usedAt:Date|null; revokedAt:Date|null }
export interface AuditEvent { id?:number; actorId:string|null; action:string; subjectId:string|null; sourceIp:string; outcome:"SUCCESS"|"DENIED"; metadata:Record<string,unknown>; createdAt:Date }
export interface Store {
 findUserByEmail(email:string):Promise<User|null>; findUserById(id:string):Promise<User|null>; createUser(user:User):Promise<void>;
 updateLoginState(id:string,failed:number,lockedUntil:Date|null):Promise<void>;
 saveRefresh(session:RefreshSession):Promise<void>; getRefresh(hash:string):Promise<RefreshSession|null>;
 consumeAndRotate(oldHash:string,replacement:RefreshSession,now:Date):Promise<boolean>; revokeFamily(familyId:string,now:Date):Promise<void>;
 addAudit(event:AuditEvent):Promise<void>; listAudit(limit:number):Promise<AuditEvent[]>;
}
