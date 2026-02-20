import { AuthRepository } from "../domain/auth.repository.js";
import { CreateAdopterDto } from "./create-user.dto.js";
import { v4 as uuidv4 } from 'uuid';
import { User } from "../domain/user.entity.js";
import * as bcrypt from 'bcrypt';
import { Injectable } from "@nestjs/common";
import { GetUserDto } from "./get-user.dto.js";
import { LoginDto } from "./login.dto.js";
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        private readonly repository: AuthRepository,
        private readonly jwtService: JwtService,
    ) { }

    async createAdopter(user: CreateAdopterDto): Promise<User> {
        const date = new Date();
        const adopterToCreate = new User(
            uuidv4(),
            user.email,
            user.name,
            "ADOPTER",
            date,
            date
        )
        const hashedPassword = await bcrypt.hash(user.password, 10);
        // const isMatch = await bcrypt.compare(inputPassword, hashToCompare);
        await this.repository.createUser(adopterToCreate, hashedPassword);
        return adopterToCreate;
    }

    async getUser(getUserDto: GetUserDto): Promise<User> {
        const user = await this.repository.getUserById(getUserDto.id);
        if (!user) {
            throw new Error('User not found');
        }
        return new User(
            user.id,
            user.email,
            user.name,
            user.role,
            user.createdAt,
            user.updatedAt
        );
    }

    async login(loginDto : LoginDto): Promise<{user: User, access_token: string}> {
        const user = await this.repository.login(loginDto.email, loginDto.password);
        if (!user) {
            throw new Error('User not found. Please check your credentials');
        }
        // Inside your AuthService
        // const payload = {
        //   iss: 'adogme-ms-auth',      // Must match 'issuer' in YAML
        //   aud: 'adogme-frontend',    // Must match 'audiences' in YAML
        //   sub: user.id,              // The User ID
        //   role: user.role // Custom claim for your logic!
        // };

        // const token = this.jwtService.sign(payload, { 
        //   privateKey: myPrivateKeyFromEnv,
        //   algorithm: 'RS256',
        //   keyid: 'adogme-key-v1'     // Must match 'kid' in your JWKS JSON
        // });
        const loggedUser = new User(
            user.id,
            user.email,
            user.name,
            user.role,
            user.createdAt,
            user.updatedAt
        );

        // Create the JWT payload
        const payload = { 
        sub: loggedUser.id, 
        role: loggedUser.role 
        };

        return {
        user: loggedUser,
        access_token: await this.jwtService.signAsync(payload),
        };
    }
}