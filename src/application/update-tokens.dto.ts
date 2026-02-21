import { IsString } from 'class-validator';

export class UpdateTokensDto {
  @IsString()
  accessToken: string;

  @IsString()
  refreshToken: string;
}