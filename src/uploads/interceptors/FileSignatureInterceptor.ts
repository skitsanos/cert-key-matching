/**
 * FileSignatureInterceptor
 *
 * Checks if file was sent and if it's header is listed as allowed type
 *
 * Useage:
 *  place it after FileInterceptor
 */

import {BadRequestException, CallHandler, ExecutionContext, Injectable, NestInterceptor} from '@nestjs/common';
import {Observable} from 'rxjs';
import {bufferStartsWith} from '../../utils/bufferUtils';

@Injectable()
export class FileSignatureInterceptor implements NestInterceptor
{
	constructor(private readonly allowedSignatures: Uint8Array[])
	{
	}

	intercept(context: ExecutionContext, next: CallHandler): Observable<any>
	{
		const ctx = context.switchToHttp();
		const req = ctx.getRequest();

		if (!req.file && !req.files)
		{
			throw new BadRequestException('The file is missing');
		}

		const files = req.files ?? [req.file];
		if (files.length === 0)
		{
			throw new BadRequestException('The file is missing');
		}
		let validFilesCount = 0;
		for (const file of files)
		{
			const {buffer} = file;
			for (const signature of this.allowedSignatures)
			{
				if (bufferStartsWith(buffer, signature))
				{
					validFilesCount++;
				}
			}
		}

		if (validFilesCount !== files.length)
		{
			throw new BadRequestException('One or more files having wrong file header');
		}

		return next.handle();
	}
}
