import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from './user/user.module';
import { APP_GUARD } from '@nestjs/core';
import { ATGuard } from './auth/guards/at.guard';

@Module({
  imports: [
    AuthModule,
    PrismaModule,
    ConfigModule.forRoot({
      isGlobal: true
    }),
    UserModule
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ATGuard
    }
  ]
})
export class AppModule { }
