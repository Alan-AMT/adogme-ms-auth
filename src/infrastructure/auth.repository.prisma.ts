import { AuthRepository } from '../domain/auth.repository.js';
import { PrismaService } from './prisma.service.js';
import { User } from '../domain/user.entity.js';
import { Role } from './generated/prisma/enums.js';
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class PrismaAuthRepository implements AuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  async createUser(user: User, password: string): Promise<void> {
    await this.prisma.user.create({
      data: {
        id: user.id,
        email: user.email,
        password: password,
        name: user.name,
        role: Role[user.role],
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    });
  }

  async getUserById(id: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({
      where: {
        id,
      },
    });
    if (!user) {
      return null;
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

  async login(email: string, password: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
      select: {
        password: true,
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    if (!user) {
      return null;
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return null;
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

  async updateRefreshTokenHash(
    id: string,
    refreshTokenHash: string,
    updatedAt: Date,
  ): Promise<void> {
    await this.prisma.user.update({
      where: {
        id,
      },
      data: {
        refreshToken: refreshTokenHash,
        updatedAt,
      },
    });
  }

  async getUserWithRefreshToken(
    id: string,
  ): Promise<{ user: User; refreshToken: string } | null> {
    const user = await this.prisma.user.findUnique({
      where: {
        id,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
        updatedAt: true,
        refreshToken: true,
      },
    });
    if (!user || !user.refreshToken) {
      return null;
    }
    return {
      user: new User(
        user.id,
        user.email,
        user.name,
        user.role,
        user.createdAt,
        user.updatedAt,
      ),
      refreshToken: user.refreshToken,
    };
  }

  async getUserPassword(id: string): Promise<string | null> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: { password: true },
    });
    return user ? user.password : null;
  }

  async updateUserPassword(
    id: string,
    newPasswordHash: string,
    updatedAt: Date,
  ): Promise<void> {
    await this.prisma.user.update({
      where: { id },
      data: {
        password: newPasswordHash,
        updatedAt,
      },
    });
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
        updatedAt: true,
      },
    });
    if (!user) {
      return null;
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

  async updateUserPasswordResetToken(
    id: string,
    resetPasswordToken: string,
    resetPasswordExpiry: Date,
    updatedAt: Date,
  ): Promise<void> {
    await this.prisma.user.update({
      where: { id },
      data: {
        resetPasswordToken,
        resetPasswordExpiry,
        updatedAt,
      },
    });
  }

  async getUserWithResetToken(email: string): Promise<{
    user: User;
    resetPasswordToken: string;
    resetPasswordExpiry: Date;
  } | null> {
    const user = await this.prisma.user.findUnique({
      where: { email: email },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
        updatedAt: true,
        resetPasswordToken: true,
        resetPasswordExpiry: true,
      },
    });
    if (!user) {
      return null;
    }
    return {
      user: new User(
        user.id,
        user.email,
        user.name,
        user.role,
        user.createdAt,
        user.updatedAt,
      ),
      resetPasswordToken: user.resetPasswordToken ?? '',
      resetPasswordExpiry: user.resetPasswordExpiry ?? new Date(),
    };
  }

  async updateUserName(
    id: string,
    name: string,
    updatedAt: Date,
  ): Promise<void> {
    await this.prisma.user.update({
      where: { id },
      data: {
        name,
        updatedAt,
      },
    });
  }
}
