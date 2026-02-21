import { Module } from '@nestjs/common';
import { AppController } from './app.controller.js';
import { PrismaService } from './infrastructure/prisma.service.js';
import { ConfigModule } from '@nestjs/config';
import { AuthService } from './application/auth.service.js';
import { AuthRepository } from './domain/auth.repository.js';
import { PrismaAuthRepository } from './infrastructure/auth.repository.prisma.js';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [ConfigModule.forRoot(),
    JwtModule.register({
      privateKey: process.env.JWT_PRIVATE_KEY ? process.env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n') : '', // Load your RS256 private key from env
      signOptions: { 
        algorithm: 'RS256',
        // expiresIn: '1h',
        issuer: 'adogme-ms-auth',
        audience: 'adogme-frontend',    // Must match 'audiences' in YAML
        keyid: 'adogme-key-v1', // Must match the 'kid' in your JWKS
      },
    }),
  ],
  controllers: [AppController],
  providers: [AuthService, PrismaService,
    { 
      provide: AuthRepository,
      useClass: PrismaAuthRepository 
    },
  ],
})
export class AppModule {}
