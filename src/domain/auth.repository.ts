import { User as UserModel } from "./user.entity.js";

export abstract class AuthRepository {
    abstract createUser(user: UserModel, password: string): Promise<void>;
    abstract getUserById(id: string): Promise<UserModel | null>;
    abstract login(email: string, password: string): Promise<UserModel | null>;
    abstract updateRefreshTokenHash(id: string, refreshTokenHash: string, updatedAt: Date): Promise<void>;
    abstract getUserWithRefreshToken(id: string): Promise<{user: UserModel, refreshToken: string} | null>;
}