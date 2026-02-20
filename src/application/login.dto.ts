// src/dogs/application/dtos/create-dog.dto.ts
import { IsString, IsEmail } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  password: string;

}