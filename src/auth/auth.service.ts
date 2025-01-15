import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthDto } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcryptjs from 'bcryptjs';
import * as argon2 from 'argon2';
import { Tokens, UserData } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
  ) { }
  async signUp(dto: AuthDto): Promise<UserData> {
    const isEmailExist = await this.prisma.user.findUnique({
      where: {
        email: dto.email
      }
    });

    if (isEmailExist) {
      throw new ConflictException("email already exists")
    }

    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: await this.hashPassword(dto.password)
      }
    });
    const session = await this.getTokens(newUser.uuid, newUser.email);

    return {
      uuid: newUser.uuid,
      email: newUser.email,
      accessToken: session.accessToken,
      refreshToken: session.refreshToken
    }
  }

  async signIn(req: Request, res: Response): Promise<UserData> {
    const tokens = await this.getTokens(req.user.uuid, req.user.email);
    await this.updateRT(req.user.uuid, tokens.refreshToken);

    res.cookie("access_token", tokens.accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 10000 // 7 hari
    });

    res.cookie("refresh_token", tokens.refreshToken, {
      httpOnly: true,
      secure: true,
      maxAge: 30 * 24 * 60 * 60 * 10000 // 30 hari
    });

    return {
      uuid: req.user.uuid,
      email: req.user.email,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    }
  }

  async validateUser(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email
      }
    });

    if (!user) {
      throw new UnauthorizedException("Invalid Crendentials.");
    }

    const isPasswordValid = await this.comparePassword(dto.password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException("Invalid Crendentials.");
    }

    // we don't need password, rt, dan salt
    const { password, rt, salt, ...userData } = user;

    return userData;

  }

  private async hashPassword(password: string): Promise<string> {
    return bcryptjs.hash(password, 10);
  }

  private async comparePassword(password: string, hashedPassword: string): Promise<boolean> {
    return bcryptjs.compare(password, hashedPassword);
  }

  async getTokens(uuid: string, email: string): Promise<Tokens> {
    const payload = {
      sub: uuid,
      email: email
    }
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        payload,
        {
          expiresIn: "15m",
          secret: this.configService.get<string>("AT_SECRET")
        }
      ),
      this.jwtService.signAsync(
        payload,
        {
          expiresIn: "30d",
          secret: this.configService.get<string>("RT_SECRET")
        }
      )
    ]);

    return {
      accessToken: at,
      refreshToken: rt
    }
  }

  async getAccessToken(uuid: string, email: string): Promise<string> {
    const payload = {
      sub: uuid,
      email
    }

    const at = await this.jwtService.signAsync(
      payload,
      {
        expiresIn: "15m",
        secret: this.configService.get<string>("AT_SECRET")
      }
    )
    return at;
  }

  private async updateRT(uuid: string, rt: string) {
    const hashedRT = await argon2.hash(rt);

    await this.prisma.user.update({
      where: {
        uuid
      },
      data: {
        rt: hashedRT
      }
    });
  }

  async validateRT(uuid: string, rt: string): Promise<Boolean> {
    const user = await this.prisma.user.findUnique({
      where: { uuid }
    });

    if (!user) {
      throw new UnauthorizedException("Invalid Credentials.");
    }

    const isRTValid = await this.compareRT(user.rt, rt)

    if (!isRTValid) {
      throw new UnauthorizedException("Invalid Credentials.")
    }

    return true
  }

  private async compareRT(hashedRT: string, rt: Buffer | string): Promise<boolean> {
    return argon2.verify(hashedRT, rt);
  }
}
