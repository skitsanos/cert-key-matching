export interface UploadPayload
{
	password: string;
	files: Express.Multer.File[];
}