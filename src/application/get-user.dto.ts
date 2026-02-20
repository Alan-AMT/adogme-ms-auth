// src/dogs/application/dtos/create-dog.dto.ts
import { IsString } from 'class-validator';

export class GetUserDto {
  @IsString()
  id: string;
}
