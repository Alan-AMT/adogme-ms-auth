import { Controller, Post, Body, UsePipes, ValidationPipe, Get, Param, HttpException, HttpStatus } from '@nestjs/common';
import { AuthService } from './application/auth.service.js';
import { CreateAdopterDto } from './application/create-user.dto.js';
import { User as UserModel } from './domain/user.entity.js';
import { LoginDto } from './application/login.dto.js';
import { UpdateTokensDto } from './application/update-tokens.dto.js';

@Controller()
@UsePipes(new ValidationPipe({ transform: true }))
export class AppController {
  constructor(private readonly authService: AuthService) {}

  @Post('adopter')
  async createAdopter(@Body() createAdopterDto: CreateAdopterDto): Promise<UserModel> {
    try {
      return await this.authService.createAdopterUseCase(createAdopterDto);
    } catch (error) {
      throw new HttpException("Error creating adopter, check if the email already exists", HttpStatus.BAD_REQUEST);
    }
  }

  @Get('user/:id')
  async getUser(@Param('id') id: string): Promise<UserModel> {
    try {
      return await this.authService.getUserUseCase({id});
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Post('user/login')
  async login(@Body() loginDto: LoginDto): Promise<{user: UserModel, accessToken: string, refreshToken: string}> {
    try {
      return await this.authService.loginUseCase(loginDto);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.UNAUTHORIZED);
    }
  }

  @Post('user/update-tokens')
  async updateTokens(@Body() updateTokensDto: UpdateTokensDto): Promise<{accessToken: string, refreshToken: string}> {
    try {
      return await this.authService.updateTokensUseCase(updateTokensDto);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }
}
