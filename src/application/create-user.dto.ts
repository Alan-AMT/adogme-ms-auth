// src/dogs/application/dtos/create-dog.dto.ts
import { IsString, IsEmail } from 'class-validator';

export class CreateAdopterDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsString()
  password: string;

}

export class CreateShelterDto {
  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  name: string;


  @IsString()
  password: string;

}