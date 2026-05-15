import {
  Controller,
  Post,
  Body,
  UsePipes,
  ValidationPipe,
  Get,
  Param,
  HttpException,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './application/auth.service.js';
import {
  CreateAdopterDto,
  CreateShelterDto,
} from './application/create-user.dto.js';
import { User as UserModel } from './domain/user.entity.js';
import { LoginDto } from './application/login.dto.js';
import { UpdateTokensDto } from './application/update-tokens.dto.js';
import { ChangePasswordDto } from './application/change-password.dto.js';
import { UserAuthorizationGuard } from './infrastructure/security/user.authorization.guard.js';
import { User as ReqUser } from './infrastructure/security/user.decorator.js';
import { ResetPasswordDto } from './application/reset-password.dto.js';


@Controller('auth-ms')
@UsePipes(new ValidationPipe({ transform: true }))
export class AppController {
  constructor(private readonly authService: AuthService) {}

  @Post('adopter')
  async createAdopter(
    @Body() createAdopterDto: CreateAdopterDto,
  ): Promise<{ user: UserModel; accessToken: string; refreshToken: string }> {
    try {
      return await this.authService.createAdopterUseCase(createAdopterDto);
    } catch (error) {
      throw new HttpException(
        'Error creating adopter, check if the email already exists',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Post('shelter')
  async createShelter(
    @Body() createShelterDto: CreateShelterDto,
  ): Promise<{ user: UserModel; accessToken: string; refreshToken: string }> {
    try {
      return await this.authService.createShelterUseCase(createShelterDto);
    } catch (error) {
      throw new HttpException(
        'Error creating shelter, check if the email already exists',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Get('user/:id')
  async getUser(@Param('id') id: string): Promise<UserModel> {
    try {
      return await this.authService.getUserUseCase({ id });
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Post('user/login')
  async login(
    @Body() loginDto: LoginDto,
  ): Promise<{ user: UserModel; accessToken: string; refreshToken: string }> {
    try {
      return await this.authService.loginUseCase(loginDto);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.UNAUTHORIZED);
    }
  }

  @Post('user/update-tokens')
  async updateTokens(
    @Body() updateTokensDto: UpdateTokensDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      return await this.authService.updateTokensUseCase(updateTokensDto);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Post('user/change-password')
  @UseGuards(UserAuthorizationGuard)
  async changePassword(
    @ReqUser('sub') userId: string,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    try {
      return await this.authService.changePasswordUseCase(userId, changePasswordDto);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }

  @Post('user/forgot-password')
  async forgotPassword(
    @Body() data: { email: string },
  ): Promise<{ message: string }> {
    return await this.authService.forgotPasswordUseCase(data.email);
  }

  @Post('user/reset-password')
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    return await this.authService.resetPasswordByTokenUseCase(resetPasswordDto);
  }
}
