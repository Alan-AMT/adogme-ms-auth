import { AuthRepository } from "../domain/auth.repository.js";
import { CreateAdopterDto } from "./create-user.dto.js";
import { v4 as uuidv4 } from 'uuid';
import { User } from "../domain/user.entity.js";
import * as bcrypt from 'bcrypt';
import { Injectable } from "@nestjs/common";
import { GetUserDto } from "./get-user.dto.js";
import { LoginDto } from "./login.dto.js";
import { JwtService } from '@nestjs/jwt';
import { UpdateTokensDto } from "./update-tokens.dto.js";

@Injectable()
export class AuthService {
    constructor(
        private readonly repository: AuthRepository,
        private readonly jwtService: JwtService,
    ) { }

    async createAdopterUseCase(user: CreateAdopterDto): Promise<User> {
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
        await this.repository.createUser(adopterToCreate, hashedPassword);
        return adopterToCreate;
    }

    async getUserUseCase(getUserDto: GetUserDto): Promise<User> {
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

    async loginUseCase(loginDto : LoginDto): Promise<{user: User, accessToken: string, refreshToken: string}> {
        const user = await this.repository.login(loginDto.email, loginDto.password);
        if (!user) {
            throw new Error('User not found. Please check your credentials');
        }
        const loggedUser = new User(
            user.id,
            user.email,
            user.name,
            user.role,
            user.createdAt,
            user.updatedAt
        );

        const {accessToken, refreshToken} = await this.generateTokens(loggedUser);

        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
        await this.repository.updateRefreshTokenHash(loggedUser.id, hashedRefreshToken, new Date());

        return {
            user: loggedUser,
            accessToken: accessToken,
            refreshToken: refreshToken,
        };
    }

    async updateTokensUseCase(updateTokensDto: UpdateTokensDto): Promise<{accessToken: string, refreshToken: string}> {
        const userId = await this.verifyTokensSignature(updateTokensDto.accessToken, updateTokensDto.refreshToken);
        
        const user = await this.validateDbRefreshToken(userId, updateTokensDto.refreshToken);
        
        const {accessToken: newAccessToken, refreshToken: newRefreshToken} = await this.generateTokens(user);

        const hashedRefreshToken = await bcrypt.hash(newRefreshToken, 10);
        await this.repository.updateRefreshTokenHash(userId, hashedRefreshToken, new Date());

        return {accessToken: newAccessToken, refreshToken: newRefreshToken};
    }

    async generateTokens(user: User): Promise<{accessToken: string, refreshToken: string}> {
        const [accessToken, refreshToken] = await Promise.all([
            // 1. Access Token (Short-lived) - Use defaul app.module.ts signOptions
            this.jwtService.signAsync(
            { sub: user.id, role: user.role },
            ),
            // 2. Refresh Token (Long-lived)
            this.jwtService.signAsync(
            { sub: user.id }, // Keep the payload minimal
            {   algorithm: 'HS256',
                secret: process.env.JWT_REFRESH_SECRET, // Use a different secret/key
                expiresIn: '7d',
            },
            ),
        ]);
        return { accessToken, refreshToken };
    }

    async verifyTokensSignature(accessToken: string, refreshToken: string): Promise<string> {
        try {
            const [accessPayload, refreshPayload] = await Promise.all([
                this.jwtService.verifyAsync(accessToken, {
                    secret: process.env.JWT_PUBLIC_KEY ? process.env.JWT_PUBLIC_KEY.replace(/\\n/g, '\n') : '', // Use your RSA Public Key
                    ignoreExpiration: true,            // This is the magic flag
                }),
                this.jwtService.verifyAsync(refreshToken, {
                    secret: process.env.JWT_REFRESH_SECRET,
                    algorithms: ['HS256'],
                }),
            ])
            if (accessPayload.sub !== refreshPayload.sub) {
                throw new Error('Access token and refresh token do not match');
            }
            return accessPayload.sub;
        } catch (e) {
            throw new Error('Either access token is invalid or refresh token has expired or is invalid');
        }
    }

    async validateDbRefreshToken(userId: string, refreshToken: string): Promise<User> {
        const userWithRefreshToken = await this.repository.getUserWithRefreshToken(userId);
        if (!userWithRefreshToken) {
            throw new Error('User or user refresh token not found');
        }
        const {user, refreshToken: dbRefreshToken} = userWithRefreshToken;

        const isMatch = await bcrypt.compare(refreshToken, dbRefreshToken);
        if (!isMatch) {
            throw new Error('Provided refresh token is not valid');
        }
        return user;
    }
}