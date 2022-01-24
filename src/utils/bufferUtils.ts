import {fileHeaders} from './fileHeaders';

import {asn1, pki, util} from 'node-forge';

export const bufferStartsWith = (buffer: Uint8Array, pattern: Uint8Array): boolean => Buffer.compare(buffer.slice(0, pattern.length), Buffer.from(pattern)) === 0;

export const base64ToDer = (base64Buffer: Uint8Array): Uint8Array => {
    const raw = base64Buffer.toString().split('\n');
    const rawBase64 = raw.slice(raw.findIndex(el => el.startsWith('-----BEGIN')) + 1, raw.findIndex(el => el.startsWith('-----END')))
        .map(el => el.trim())
        .join('');

    return Buffer.from(rawBase64, 'base64');
};

/**
 * Coverts NodeJs buffer into node-forge driven DER buffer
 * @param buffer
 */
export const bufferToDerBuffer = (buffer: Uint8Array) => util.createBuffer(buffer);

export const base64ToDerBuffer = (buffer: Uint8Array) => util.createBuffer(util.decode64(typeof buffer === 'string' ? buffer : buffer.toString()));


const isFullChain = (buffer: Uint8Array): boolean => {
    const r = /-----BEGIN CERTIFICATE-----/gu;
    const matches = buffer.toString().match(r);
    if (matches && matches?.length >= 2) {
        return true;
    }

    return false;
};

/**
 * Loops through all the known file headers to identify file format
 * @param buffer
 */
export const whatFile = (buffer: Uint8Array): Record<string, any> => {
    for (const signature of Object.entries(fileHeaders)) {
        const [key, pattern] = signature;

        if (bufferStartsWith(buffer, Buffer.from(pattern))) {
            switch (true) {
                // A PEM file must consist of a private key, a CA server certificate,
                // and additional certificates that make up the trust chain.
                // The trust chain must contain a root certificate and, if needed, intermediate certificates.
                case key === 'PEM_KEY' && isFullChain(buffer):
                case key === 'PEM_CERTIFICATE' && isFullChain(buffer):
                    return {type: `CERTIFICATE_FULL_CHAIN`};

                case key === 'PRIVATE_KEY_2048':
                    const hex = bufferToDerBuffer(buffer);
                    try {
                        const certificate = pki.certificateFromAsn1(asn1.fromDer(hex));
                        return {type: 'CERTIFICATE_FULL_CHAIN', certificate};
                    } catch (e) {
                        return {type: key.toUpperCase()};
                    }

                //do something with der/asn1 bufer
                //console.log(asn1.fromDer(hex).value[0].value);
                //console.log(pki.privateKeyFromAsn1(asn1.fromDer(hex)))


                default:
                    return {type: key.toUpperCase()};
            }
        }
    }

    return {type: 'UNKNOWN'};
};