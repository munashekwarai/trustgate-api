import Fastify from "fastify";
import { readFileSync } from "node:fs";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { Pool } from "pg";
import { z } from "zod";
import { AppError, authorize, type Principal } from "./domain.js";
import { AuthService } from "./auth-service.js";
import { PostgresStore } from "./postgres-store.js";
import { TokenService } from "./tokens.js";

const registration=z.object({email:z.email().max(254),password:z.string().min(12).max(128)}).strict();
const login=registration;const refresh=z.object({refreshToken:z.string().min(40).max(200)}).strict();

export async function createServer(store:ConstructorParameters<typeof AuthService>[0],tokens:TokenService){
 const app=Fastify({logger:true,trustProxy:false,bodyLimit:16_384});const auth=new AuthService(store,tokens);
 await app.register(helmet,{global:true});await app.register(rateLimit,{global:true,max:100,timeWindow:"1 minute"});
 app.setErrorHandler((error,request,reply)=>{if(error instanceof AppError)return reply.code(error.status).send({error:{code:error.code,message:error.message,requestId:request.id}});if(error instanceof z.ZodError)return reply.code(422).send({error:{code:"VALIDATION_ERROR",message:"request validation failed",issues:error.issues.map(x=>({path:x.path.join("."),message:x.message})),requestId:request.id}});request.log.error(error);return reply.code(500).send({error:{code:"INTERNAL_ERROR",message:"request failed",requestId:request.id}})});
 const ip=(request:any)=>request.ip as string;
 app.get("/health",async()=>({status:"ok"}));
 app.post("/auth/register",{config:{rateLimit:{max:10,timeWindow:"1 minute"}}},async(req,reply)=>reply.code(201).send(await auth.register(...(()=>{const x=registration.parse(req.body);return [x.email,x.password,ip(req)] as const})())));
 app.post("/auth/login",{config:{rateLimit:{max:10,timeWindow:"1 minute"}}},async req=>{const x=login.parse(req.body);return auth.login(x.email,x.password,ip(req))});
 app.post("/auth/refresh",async req=>{const x=refresh.parse(req.body);return auth.refresh(x.refreshToken,ip(req))});
 async function principal(req:any):Promise<Principal>{const header=req.headers.authorization;if(!header?.startsWith("Bearer "))throw new AppError("AUTHENTICATION_REQUIRED",401,"authentication required");try{return await tokens.verify(header.slice(7))}catch{throw new AppError("INVALID_ACCESS_TOKEN",401,"access token invalid")}}
 app.get("/me",async req=>{const actor=await principal(req);const user=await store.findUserById(actor.id);return {id:user?.id,email:user?.email,role:user?.role}});
 app.get("/audit",async req=>{const actor=await principal(req);if(!authorize(actor,"audit:read")){await store.addAudit({actorId:actor.id,action:"AUDIT_READ",subjectId:null,sourceIp:ip(req),outcome:"DENIED",metadata:{},createdAt:new Date()});throw new AppError("FORBIDDEN",403,"permission denied")}return {events:await store.listAudit(100)}});
 return app;
}

if(process.env.NODE_ENV!=="test"){
 const secret=process.env.TOKEN_SECRET ?? (process.env.TOKEN_SECRET_FILE ? readFileSync(process.env.TOKEN_SECRET_FILE,"utf8").trim() : undefined);if(!secret)throw new Error("TOKEN_SECRET or TOKEN_SECRET_FILE is required");
 const url=process.env.DATABASE_URL;if(!url)throw new Error("DATABASE_URL is required");
 const app=await createServer(new PostgresStore(new Pool({connectionString:url,max:10,ssl:process.env.PGSSL==="require"?{rejectUnauthorized:true}:undefined})),new TokenService(secret));
 await app.listen({host:process.env.HOST??"127.0.0.1",port:Number(process.env.PORT??3000)});
}
