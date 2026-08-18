import { randomBytes, scrypt as callbackScrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
const scrypt = promisify(callbackScrypt);
const KEY_LENGTH = 64;

export function validatePassword(password: string): void {
  if (password.length < 12 || password.length > 128) throw new Error("password must contain 12 to 128 characters");
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password))
    throw new Error("password must include upper-case, lower-case, and numeric characters");
}
export async function hashPassword(password: string): Promise<string> {
  validatePassword(password); const salt=randomBytes(16); const key=await scrypt(password,salt,KEY_LENGTH) as Buffer;
  return `scrypt$${salt.toString("base64url")}$${key.toString("base64url")}`;
}
export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [scheme,saltText,keyText]=encoded.split("$");
  if (scheme!=="scrypt" || !saltText || !keyText) return false;
  const expected=Buffer.from(keyText,"base64url"); const actual=await scrypt(password,Buffer.from(saltText,"base64url"),expected.length) as Buffer;
  return actual.length===expected.length && timingSafeEqual(actual,expected);
}
