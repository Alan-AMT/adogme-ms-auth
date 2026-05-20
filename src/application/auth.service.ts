import { AuthRepository } from '../domain/auth.repository.js';
import { CreateAdopterDto } from './create-user.dto.js';
import { v4 as uuidv4 } from 'uuid';
import { User } from '../domain/user.entity.js';
import * as bcrypt from 'bcrypt';
import { HttpStatus, Injectable } from '@nestjs/common';
import { GetUserDto } from './get-user.dto.js';
import { LoginDto } from './login.dto.js';
import { JwtService } from '@nestjs/jwt';
import { UpdateTokensDto } from './update-tokens.dto.js';
import { ChangePasswordDto } from './change-password.dto.js';
import { HttpErrorByCode } from '@nestjs/common/utils/http-error-by-code.util.js';
import crypto from "crypto";
import { ResetPasswordDto } from './reset-password.dto.js';
import { EmailSenderPort, EmailTemplate } from '../domain/email-sender.port.js';

@Injectable()
export class AuthService {
  constructor(
    private readonly repository: AuthRepository,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailSenderPort,
  ) {}

  async createAdopterUseCase(user: CreateAdopterDto): Promise<{ user: User; accessToken: string; refreshToken: string }> {
    const date = new Date();
    const adopterToCreate = new User(
      uuidv4(),
      user.email,
      user.name,
      'applicant',
      date,
      date,
    );
    const hashedPassword = await bcrypt.hash(user.password, 10);
    await this.repository.createUser(adopterToCreate, hashedPassword);
    const { accessToken, refreshToken } = await this.generateTokens(adopterToCreate);

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.repository.updateRefreshTokenHash(
      adopterToCreate.id,
      hashedRefreshToken,
      new Date(),
    );
    return {
      user: adopterToCreate,
      accessToken,
      refreshToken,
    };
  }

  async createShelterUseCase(user: CreateAdopterDto): Promise<{ user: User; accessToken: string; refreshToken: string }> {
    const date = new Date();
    const shelterToCreate = new User(
      uuidv4(),
      user.email,
      user.name,
      'shelter',
      date,
      date,
    );
    const hashedPassword = await bcrypt.hash(user.password, 10);
    await this.repository.createUser(shelterToCreate, hashedPassword);
    const { accessToken, refreshToken } = await this.generateTokens(shelterToCreate);

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.repository.updateRefreshTokenHash(
      shelterToCreate.id,
      hashedRefreshToken,
      new Date(),
    );
    this.emailService.sendEmail({
      to: 'alanx015@hotmail.com',
      subject: 'Nuevo shelter registrado',
      template: EmailTemplate.SHELTER_CREATED,
      context: { userId: shelterToCreate.id, userEmail: shelterToCreate.email },
    });
    return {
      user: shelterToCreate,
      accessToken,
      refreshToken,
    };
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
      user.updatedAt,
    );
  }

  async loginUseCase(
    loginDto: LoginDto,
  ): Promise<{ user: User; accessToken: string; refreshToken: string }> {
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
      user.updatedAt,
    );

    const { accessToken, refreshToken } = await this.generateTokens(loggedUser);

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.repository.updateRefreshTokenHash(
      loggedUser.id,
      hashedRefreshToken,
      new Date(),
    );

    return {
      user: loggedUser,
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }

  async updateTokensUseCase(
    updateTokensDto: UpdateTokensDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const userId = await this.verifyTokensSignature(
      updateTokensDto.accessToken,
      updateTokensDto.refreshToken,
    );

    const user = await this.validateDbRefreshToken(
      userId,
      updateTokensDto.refreshToken,
    );

    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      await this.generateTokens(user);

    const hashedRefreshToken = await bcrypt.hash(newRefreshToken, 10);
    await this.repository.updateRefreshTokenHash(
      userId,
      hashedRefreshToken,
      new Date(),
    );

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async changePasswordUseCase(
    userId: string,
    changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    const currentPasswordHash = await this.repository.getUserPassword(userId);
    if (!currentPasswordHash) {
      throw new Error('User not found');
    }

    const isMatch = await bcrypt.compare(
      changePasswordDto.currentPassword,
      currentPasswordHash,
    );
    if (!isMatch) {
      throw new Error('Invalid current password');
    }

    const newPasswordHash = await bcrypt.hash(
      changePasswordDto.newPassword,
      10,
    );
    await this.repository.updateUserPassword(
      userId,
      newPasswordHash,
      new Date(),
    );

    return { message: 'Password updated successfully' };
  }

  async generateTokens(
    user: User,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const [accessToken, refreshToken] = await Promise.all([
      // 1. Access Token (Short-lived) - Use defaul app.module.ts signOptions
      this.jwtService.signAsync({ sub: user.id, role: user.role, name: user.name, email: user.email }),
      // 2. Refresh Token (Long-lived)
      this.jwtService.signAsync(
        { sub: user.id }, // Keep the payload minimal
        {
          algorithm: 'HS256',
          secret: process.env.JWT_REFRESH_SECRET, // Use a different secret/key
          expiresIn: '7d',
        },
      ),
    ]);
    return { accessToken, refreshToken };
  }

  async verifyTokensSignature(
    accessToken: string,
    refreshToken: string,
  ): Promise<string> {
    try {
      const [accessPayload, refreshPayload] = await Promise.all([
        this.jwtService.verifyAsync(accessToken, {
          secret: process.env.JWT_PUBLIC_KEY
            ? process.env.JWT_PUBLIC_KEY.replace(/\\n/g, '\n')
            : '', // Use your RSA Public Key
          ignoreExpiration: true, // This is the magic flag
        }),
        this.jwtService.verifyAsync(refreshToken, {
          secret: process.env.JWT_REFRESH_SECRET,
          algorithms: ['HS256'],
        }),
      ]);
      if (accessPayload.sub !== refreshPayload.sub) {
        throw new Error('Access token and refresh token do not match');
      }
      return accessPayload.sub;
    } catch (e) {
      throw new Error(
        'Either access token is invalid or refresh token has expired or is invalid',
      );
    }
  }

  async validateDbRefreshToken(
    userId: string,
    refreshToken: string,
  ): Promise<User> {
    const userWithRefreshToken =
      await this.repository.getUserWithRefreshToken(userId);
    if (!userWithRefreshToken) {
      throw new Error('User or user refresh token not found');
    }
    const { user, refreshToken: dbRefreshToken } = userWithRefreshToken;

    const isMatch = await bcrypt.compare(refreshToken, dbRefreshToken);
    if (!isMatch) {
      throw new Error('Provided refresh token is not valid');
    }
    return user;
  }

  async forgotPasswordUseCase(userEmail: string): Promise<{ message: string }> {
    const user = await this.repository.getUserByEmail(userEmail);
    if (!user) {
      return { message: 'If the account exists, an email was sent.' };
    }
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000);
    await this.repository.updateUserPasswordResetToken(
      user.id,
      resetToken,
      resetTokenExpiry,
      new Date(),
    );
    this.emailService.sendEmail({
      to: userEmail,
      subject: 'Reset Password',
      template: EmailTemplate.PASSWORD_RESET,
      context: {
        url: `https://adogme.org/reset-password?token=${resetToken}&email=${userEmail}`,
        name: user.name,
      },
    });
    return { message: 'If the account exists, an email was sent.' };
  }

  async resetPasswordByTokenUseCase(resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
    const data = await this.repository.getUserWithResetToken(resetPasswordDto.email);
    if (!data) {
      throw new HttpErrorByCode[HttpStatus.UNAUTHORIZED]('Invalid credentials');
    }
    const { user, resetPasswordToken, resetPasswordExpiry } = data;
    const currentDate = new Date();
    if (resetPasswordExpiry <= currentDate || resetPasswordToken !== resetPasswordDto.token) {
      throw new HttpErrorByCode[HttpStatus.UNAUTHORIZED]('Invalid credentials');
    }
    const newPasswordHash = await bcrypt.hash(
      resetPasswordDto.newPassword,
      10,
    );
    await this.repository.updateUserPassword(
      user.id,
      newPasswordHash,
      new Date(),
    );
    //Send confirmation email
    return { message: 'Password reset successfully' };
  }
}
