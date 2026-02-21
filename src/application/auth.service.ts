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
        const payload = await this.jwtService.verifyAsync(updateTokensDto.accessToken, {
            secret: process.env.JWT_PUBLIC_KEY, // Use your RSA Public Key
            ignoreExpiration: true,            // This is the magic flag
        });
        const userId = payload.sub;
        
        const userWithRefreshToken = await this.repository.getUserWithRefreshToken(userId);
        if (!userWithRefreshToken) {
            throw new Error('User or user refresh token not found');
        }
        const {user, refreshToken} = userWithRefreshToken;

        const isMatch = await bcrypt.compare(updateTokensDto.refreshToken, refreshToken);
        if (!isMatch) {
            throw new Error('Invalid refresh token');
        }
        
        const {accessToken: newAccessToken, refreshToken: newRefreshToken} = await this.generateTokens(user);
        const hashedRefreshToken = await bcrypt.hash(newRefreshToken, 10);
        await this.repository.updateRefreshTokenHash(userId, hashedRefreshToken, new Date());

        return {accessToken: newAccessToken, refreshToken: newRefreshToken};
    }

    async generateTokens(user: User): Promise<{accessToken: string, refreshToken: string}> {
        const [accessToken, refreshToken] = await Promise.all([
            // 1. Access Token (Short-lived)
            this.jwtService.signAsync(
            { sub: user.id, role: user.role },
            {
                secret: process.env.JWT_ACCESS_SECRET, // Your RS256 Private Key
                expiresIn: '1h',
            },
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
}