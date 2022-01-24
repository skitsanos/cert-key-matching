import {asn1, pkcs12, pki} from 'node-forge';
import {base64ToDerBuffer, bufferStartsWith, bufferToDerBuffer} from './bufferUtils';
import {fileHeaders} from './fileHeaders';
import {ExecResult} from './ExecResult';
import {Buffer} from 'buffer';
import {isEqual} from 'lodash';


export const getPrivateKey = (file: any, password?: string): ExecResult =>
{
	if (typeof file === 'object' && Object.prototype.hasOwnProperty.call(file, 'buffer'))
	{
		let derBuffer;
		if (bufferStartsWith(file.buffer, Buffer.from(fileHeaders.DER_FILE)))
		{
			derBuffer = bufferToDerBuffer(file.buffer);
		}
		else
		{
			derBuffer = base64ToDerBuffer(file.buffer);
		}

		const payload = asn1.fromDer(derBuffer);

		try
		{
			const privateKey = pki.decryptRsaPrivateKey(file.buffer, password);
			const publicKey = pki.rsa.setPublicKey(privateKey.n, privateKey.e);
			return {code: 0, data: {privateKey, publicKey}};
		}
		catch (e)
		{
		}

		try
		{
			return {code: 0, data: {privateKey: pki.privateKeyFromAsn1(payload)}};
		}
		catch (e)
		{
		}

		return {code: 1, message: 'Failed to get private key'};
	}

	try
	{
		if (typeof file === 'object' && Buffer.isBuffer(file))
		{
			return {code: 0, data: pki.privateKeyFromPem(file.toString())};
		}

		console.log('got pem');

		return {code: 0, data: pki.privateKeyFromPem(file)};
	}
	catch (e)
	{
		return {code: 1, message: e.message};
	}
};

export const getCertificateFromFile = (file: any, password?: string): ExecResult =>
{
	try
	{
		if (typeof file === 'object' && Object.prototype.hasOwnProperty.call(file, 'buffer'))
		{
			let derBuffer;
			if (bufferStartsWith(file.buffer, Buffer.from(fileHeaders.DER_FILE)))
			{
				derBuffer = bufferToDerBuffer(file.buffer);
			}
			else
			{
				derBuffer = base64ToDerBuffer(file.buffer);
			}

			const payload = asn1.fromDer(derBuffer);

			if (payload.composed)
			{
				//pfx has less data within the same der payload
				const found = [...payload.value].filter(el => Object.keys(el).includes('bitStringContents')).length > 0;
				if (!found)
				{
					//most likely pfx
					const pkcs = pkcs12.pkcs12FromAsn1(payload, password);
					const certificate = pkcs.safeContents
						.find(co => co.safeBags.find(b => b.cert))
						.safeBags.find(c => c.cert.extensions && !c.cert.extensions.find(e => e.cA)).cert;

					const privateKey = pkcs.safeContents.find(c => c.safeBags.find(b => b.key)).safeBags[0].key;

					return {
						code: 0,
						data: {
							certificate,
							privateKey
						}
					};
				}

				return {
					code: 0,
					data: {certificate: pki.certificateFromAsn1(payload)}
				};
			}
			else
			{
				const rawFile = file.buffer.toString();

				return {
					code: 0,
					data: {
						certificate: pki.certificateFromPem(rawFile)
					}
				};
			}
		}

		//if payload sent is buffer or string
		if (typeof file === 'string')
		{
			return {
				code: 0,
				data: {
					certificate: pki.certificateFromPem(file)
				}
			};
		}

		if (Buffer.isBuffer(file))
		{
			return {
				code: 0,
				data: {
					certificate: pki.certificateFromPem(file.toString())
				}
			};
		}

		return {
			code: 400,
			message: 'Unsupported format'
		};

	}
	catch (e)
	{
		console.log(e.message);
		const isInvalidPassword = e.message.match(/Invalid password/giu);

		return {
			code: isInvalidPassword ? 403 : 1,
			message: e.message
		};
	}
};

export const isPemCertificate = (file: any): boolean =>
{
	//"CERTIFICATE", "X509 CERTIFICATE", or "TRUSTED CERTIFICATE"
	if (typeof file === 'object' && Object.prototype.hasOwnProperty.call(file, 'buffer'))
	{
		if (bufferStartsWith(file.buffer, Buffer.from(fileHeaders.DER_FILE)))
		{
			return false;
		}

		const rawFile = file.buffer.toString();
		if (rawFile.match(/CERTIFICATE/giu))
		{
			return true;
		}
	}
	else
	{
		if (typeof file === 'string' && file.match(/CERTIFICATE/giu))
		{
			return true;
		}

		if (Buffer.isBuffer(file) && file.toString().match(/CERTIFICATE/giu))
		{
			return true;
		}
	}

	return false;
};

export const isPemKey = (file: any): boolean =>
{
	const rx = /PRIVATE KEY/giu;

	return !!(
		(typeof file === 'string' && file.match(rx)) ||
		(Buffer.isBuffer(file) && file.toString().match(rx)) ||
		(typeof file === 'object' && Object.prototype.hasOwnProperty.call(file, 'buffer') && file.buffer.toString().match(rx)));
};

export const isKeyMatched = (source: any, target: any) => isEqual(source.e, target.e) && isEqual(source.n, target.n);