/**
 * FileCheckInterceptor
 *
 * Checks if file was sent and if it's size is more than a zero bytes
 *
 * Useage:
 *  place it after FileInterceptor
 */

import {BadRequestException, CallHandler, ExecutionContext, Injectable, NestInterceptor} from '@nestjs/common';
import {Observable} from 'rxjs';

@Injectable()
export class FileCheckInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        const ctx = context.switchToHttp();
        const req = ctx.getRequest();
        if (!req.file) {
            throw new BadRequestException('The file is missing');
        }

        if (req.file.size === 0) {
            throw new BadRequestException('The file is empty');
        }

        return next.handle();
    }
}
