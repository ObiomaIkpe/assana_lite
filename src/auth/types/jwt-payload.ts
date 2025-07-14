// Somewhere at the top of your jwt.strategy.ts
export interface JwtPayload {
  id: number;
  email: string;
  role: string;
}
