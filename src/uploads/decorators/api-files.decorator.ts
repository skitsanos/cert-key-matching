import {applyDecorators, UseInterceptors} from '@nestjs/common';
import {FilesInterceptor} from '@nestjs/platform-express';
import {MulterOptions} from '@nestjs/platform-express/multer/interfaces/multer-options.interface';
import {ApiBody, ApiConsumes} from '@nestjs/swagger';
import {FileSignatureInterceptor} from '../interceptors/FileSignatureInterceptor';

export function ApiFiles(
    fieldName = 'files',
    required = false,
    maxCount = 10,
    allowedSignatures?: Uint8Array[],
    localOptions?: MulterOptions
) {
    return applyDecorators(
        UseInterceptors(
            FilesInterceptor(fieldName, maxCount, localOptions),
            new FileSignatureInterceptor(allowedSignatures)
        ),
        ApiConsumes('multipart/form-data'),
        ApiBody({
            schema: {
                type: 'object',
                required: required ? [fieldName] : [],
                properties: {
                    [fieldName]: {
                        type: 'array',
                        items: {
                            type: 'string',
                            format: 'binary'
                        }
                    }
                }
            }
        })
    );
}
