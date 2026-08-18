export const roles = ["ADMIN", "MANAGER", "USER", "AUDITOR"] as const;
export type Role = (typeof roles)[number];
export type Permission = "users:read:any" | "users:read:own" | "users:manage" | "audit:read" | "records:write:own";

export const rolePermissions: Readonly<Record<Role, ReadonlySet<Permission>>> = {
  ADMIN: new Set(["users:read:any", "users:read:own", "users:manage", "audit:read", "records:write:own"]),
  MANAGER: new Set(["users:read:any", "users:read:own", "records:write:own"]),
  USER: new Set(["users:read:own", "records:write:own"]),
  AUDITOR: new Set(["audit:read"]),
};

export interface Principal { id: string; role: Role; tokenId: string }

export function authorize(principal: Principal, permission: Permission, ownerId?: string): boolean {
  if (!rolePermissions[principal.role].has(permission)) return false;
  return !permission.endsWith(":own") || principal.id === ownerId;
}

export class AppError extends Error {
  constructor(public readonly code: string, public readonly status: number, message: string) { super(message); }
}
