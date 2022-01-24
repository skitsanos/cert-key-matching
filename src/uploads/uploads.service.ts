import {Injectable} from '@nestjs/common';

@Injectable()
export class UploadsService
{
    uploadFile(file: Express.Multer.File)
    {
        return 'Uploads file';
    }
}