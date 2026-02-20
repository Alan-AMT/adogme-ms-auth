import { Controller, Post, Body, UsePipes, ValidationPipe, Get, Param, HttpException, HttpStatus, StreamableFile } from '@nestjs/common';
import { AuthService } from './application/auth.service.js';
import { CreateAdopterDto } from './application/create-user.dto.js';
import { User as UserModel } from './domain/user.entity.js';
import { LoginDto } from './application/login.dto.js';

@Controller()
@UsePipes(new ValidationPipe({ transform: true }))
export class AppController {
  constructor(private readonly authService: AuthService) {}

  @Post('adopter')
  async createAdopter(@Body() createAdopterDto: CreateAdopterDto): Promise<UserModel> {
    return await this.authService.createAdopter(createAdopterDto);
  }

  @Get('user/:id')
  async getUser(@Param('id') id: string): Promise<UserModel> {
    try {
      return await this.authService.getUser({id});
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }

  @Post('user/login')
  async login(@Body() loginDto: LoginDto): Promise<{user: UserModel, access_token: string}> {
    try {
      return await this.authService.login(loginDto);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.UNAUTHORIZED);
    }
  }

  @Get('well-known/jwks.json')
  getJwks() {
    return {
      "keys": [
          {
              "kty": "RSA",
              "alg": "RS256",
              "use": "sig",
              "kid": "adogme-key-v1",
              "n": "rU6UpiaysddOzh1pZ5olmLxw6ZyYVs8RbKEEkHHn_8rFweaDmIbEeP0mX6pLpZxWc2ZZveVWVIJHXXE2Nq9a5BLaF3PGsaas155uzLPUCixrgdi6crCVB5vIcv0Kz5L4Fk8n21BUG8Jy6qpJ2AVdJ0CIVtq2qLb9qPD2hDpqEJRSCz2HDuuhSXXNIJ1HVcJRo0RsBcG_X6eF0fH63w6yP4X5uUgC2JiHad6JBZimYRa53-f-aB9hBinE9bOPfU5Tly2rOwQy3zWbLISssbN49f06jHflluaWPOl0tB1ap88wd2Ys_tJOgzvHa_eTm8fkQBv-EpBPkeIcZegvLSVS4w",
              "e": "AQAB"
          }
      ]
    };
  }
}
