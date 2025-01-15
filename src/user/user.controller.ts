import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { ATGuard } from 'src/auth/guards/at.guard';
import { Public } from 'src/common/decorator/is-public/is-public.decorator';
import { Request } from 'express';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService
  ) { }

  @Get("test")
  test(@Req() req: Request){
    console.log(req.user)
  }

}
