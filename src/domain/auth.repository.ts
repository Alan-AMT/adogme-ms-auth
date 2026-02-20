import { User as UserModel } from "./user.entity.js";

export abstract class AuthRepository {
    abstract createUser(user: UserModel, password: string): Promise<void>;
    abstract getUserById(id: string): Promise<UserModel | null>;
    abstract login(email: string, password: string): Promise<UserModel | null>;
}