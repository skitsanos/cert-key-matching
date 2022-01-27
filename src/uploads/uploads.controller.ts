import {BadRequestException, Body, Controller, Logger, Post, UploadedFiles} from '@nestjs/common';
import {ApiTags} from '@nestjs/swagger';
import {UploadsService} from './uploads.service';
import {ApiFiles} from './decorators/api-files.decorator';
import {fileHeaders} from '../utils/fileHeaders';
import {
	getCertificateFromFile,
	getPrivateKey,
	isKeyMatched,
	isPemKey,
	storeCerificate,
	storePrivateKey
} from '../utils/forgeUtils';
import {UploadPayload} from '../utils/schemas/UploadPayload';

import {join as pathJoin} from 'path';

//https://notiz.dev/blog/type-safe-file-uploads

const keysStore = pathJoin(__dirname, '../../(store)');

@Controller('uploads')
@ApiTags('uploads')
export class UploadsController
{
	private readonly logger: Logger = new Logger('File Uploader');

	constructor(private readonly filesService: UploadsService)
	{
	}

	@Post()
	/*@ApiFileFields([
		{name: 'file', maxCount: 1, required: true},
		{name: 'regenerateRoot', maxCount: 1},
		{name: 'password', maxCount: 1}
	])*/
	@ApiFiles('file', true, 10, [
		Buffer.from(fileHeaders.PEM_PRIVATE_KEY),
		Buffer.from(fileHeaders.PEM_PUBLIC_KEY),
		Buffer.from(fileHeaders.PEM_CERTIFICATE),
		Buffer.from(fileHeaders.PEM_ENCRYPTED_KEY),
		Buffer.from(fileHeaders.PKCS7_CERTIFICATE),
		Buffer.from(fileHeaders.PKCS10_CERTIFICATE),
		Buffer.from(fileHeaders.PKCS11_CERTIFICATE),
		Buffer.from(fileHeaders.PKCS12_CERTIFICATE),
		Buffer.from(fileHeaders.DER_FILE)
	])
	uploadFiles(@Body() body: UploadPayload, @UploadedFiles() files: Express.Multer.File[])
	{
		//https://app.id123.io/free-tools/key-generator/
		const {password} = body;

		const orphans = [];

		// extract key and certificate
		for (const file of files)
		{
			if (isPemKey(file))
			{
				//process non-certificate files
				this.logger.log(`*${file.originalname} processing as a key`);

				const {code, data, message} = getPrivateKey(file, password);
				if (code > 0)
				{
					this.logger.log(`${file.originalname}: ${message}`);
				}
				else
				{
					orphans.push({
						type: 'privateKey',
						file: file.originalname,
						data
					});
				}
			}
			else
			{
				//check if file is a certificate
				const {code, data, message} = getCertificateFromFile(file, password);
				if (code === 0)
				{
					//certificate file
					const {validity} = data.certificate;

					orphans.push({
						type: 'certificate',
						file: file.originalname,
						data
					});

					this.logger.log(`Certificate valid until ${validity.notAfter}`);
				}
				else
				{
					this.logger.log(message);

					if (code === 403)
					{
						throw new BadRequestException(`${file.originalname}: ${message}`);
					}
				}
			}

		}

		this.logger.log('Processing files ...');
		const unmatchedKeys = orphans.filter(el => el.type === 'privateKey');
		const unmatchedCertificates = orphans.filter(el => el.type === 'certificate' && !el.data.privateKey);
		const matchedCertificates = orphans.filter(el => el.type === 'certificate' && el.data.privateKey);

		//console.log(unmatchedKeys);
		//console.log(unmatchedCertificates[0].data.certificate.privateKey);

		//now we can do some matching
		const pairs = [
			...matchedCertificates.map(el => el.data)
		];

		for (const found of unmatchedCertificates)
		{
			const {certificate} = found.data;

			for (const foundKey of unmatchedKeys)
			{
				const {publicKey, privateKey} = foundKey.data;
				//compare certificate's public key with the public key generated out of private key
				if (isKeyMatched(certificate.publicKey, publicKey))
				{
					pairs.push({
						certificate,
						privateKey
					});
				}
			}
		}

		if (pairs.length > 0)
		{
			const [foundPair] = pairs;
			//store private key
			const {privateKey, certificate} = foundPair;

			const {
				code: codeCert,
				message: messageCert
			} = storeCerificate(certificate, pathJoin(keysStore, 'certificate.pem'));
			if (codeCert > 0)
			{
				throw new BadRequestException(`Failed to store the private key: ${messageCert}`);
			}

			const {code: codeKey, message: messageKey} = storePrivateKey(privateKey, pathJoin(keysStore, 'key.pem'));
			if (codeKey > 0)
			{
				throw new BadRequestException(`Failed to store the private key: ${messageKey}`);
			}

			this.logger.log('Certificate and keys saved');
		}
	}
}
