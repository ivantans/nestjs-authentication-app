import { ExecutionContext, HttpStatus, Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { plainToClass } from "class-transformer";
import { Request, Response } from "express";
import { Observable } from "rxjs";
import { AuthDto } from "../dto";
import { validate } from "class-validator";

@Injectable()
export class LocalAuthGuard extends AuthGuard("local") {

  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    const body = plainToClass(AuthDto, request.body);

    const errors = await validate(body);

    const errorMessages = errors.flatMap(({ constraints }) =>
      Object.values(constraints),
    );

    if (errorMessages.length > 0) {
      response.status(HttpStatus.BAD_REQUEST).json({
        message: errorMessages,
        error: "Bad Request",
        statusCode: 400
      })
    }

    return super.canActivate(context) as boolean | Promise<boolean>;
  }
}