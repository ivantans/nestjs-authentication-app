import { Body, Controller, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { UserData } from './types';
import { BaseResponseApi } from 'src/common/type';
import { Request } from 'express';
import { LocalAuthGuard } from './guards';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService
  ) { }


  @Post("signup")
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Body() dto: AuthDto): Promise<BaseResponseApi<UserData>> {
    const response = await this.authService.signUp(dto);
    return {
      statusCode: HttpStatus.CREATED,
      statusMessage: HttpStatus[201],
      data: response
    }
  }

  @UseGuards(LocalAuthGuard)
  @Post("signin")
  async signIn(@Req() req: Request, @Body() dto: AuthDto): Promise<BaseResponseApi<UserData>> {
    const tokens = await this.authService.signIn(req);
    return {
      statusCode: HttpStatus.CREATED,
      statusMessage: HttpStatus[201],
      data: tokens
    }
  }
  
}
