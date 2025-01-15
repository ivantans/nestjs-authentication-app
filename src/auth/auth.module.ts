import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { ATStrategy, LocalAuthStrategy } from './strategies';
import { LocalAuthGuard } from './guards';
import { RTStrategy } from './strategies/rt.strategy';

@Module({
  imports: [
    JwtModule.register({})
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalAuthStrategy, ATStrategy, RTStrategy],
})
export class AuthModule {}
