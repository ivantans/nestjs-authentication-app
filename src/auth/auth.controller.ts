import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { UserData } from './types';
import { BaseResponseApi } from 'src/common/type';
import { Request, Response } from 'express';
import { LocalAuthGuard } from './guards';
import { Public } from 'src/common/decorator/is-public/is-public.decorator';
import { RTGuard } from './guards/rt.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService
  ) { }

  @Public()
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

  @Public()
  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @Post("signin")
  async signIn(@Req() req: Request, @Res() res: Response): Promise<BaseResponseApi<UserData>> {
    const tokens = await this.authService.signIn(req, res);
    return res.status(HttpStatus.OK).json({
      statusCode: HttpStatus.CREATED,
      statusMessage: HttpStatus[201],
      data: tokens
    });
  }

  @Public()
  @UseGuards(RTGuard)
  @HttpCode(200)
  @Post("refresh-access-token")
  async refreshAT(@Req() req: Request): Promise<BaseResponseApi<Record<string, string>>> {
    const accessToken = await this.authService.getAccessToken(req.user.uuid, req.user.email)
    return {
      statusCode: HttpStatus.OK,
      statusMessage: HttpStatus[200],
      data: {
        accessToken
      }
    }
  }

}
