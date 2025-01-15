import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";
import { AuthService } from "../auth.service";
import { TokenPayload } from "../types";

@Injectable()
export class RTStrategy extends PassportStrategy(Strategy, "jwt-rt"){
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService
  ){
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        RTStrategy.extractJWT
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>("RT_SECRET"),
      passReqToCallback: true
    });
  }

  private static extractJWT(req: Request): string | null {
    if(req.cookies && req.cookies.refresh_token){
      return req.cookies.refresh_token;
    }
    return null
  }

  private getRefreshToken(req: Request): string | null {
    if (req.cookies?.refresh_token) {
      return req.cookies.refresh_token;
    }
    if (req.headers.authorization?.startsWith("Bearer ")) {
      return req.headers.authorization.split(" ")[1];
    }
    return null;
  }
  
  async validate(req: Request, payload: TokenPayload){
    const token = this.getRefreshToken(req);
    await this.authService.validateRT(payload.sub, token);
    return payload;
  }
}