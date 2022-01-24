export const fileHeaders = {
    PEM_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----',
    PEM_PUBLIC_KEY: '-----BEGIN PUBLIC KEY-----',
    PEM_ENCRYPTED_KEY: '-----BEGIN ENCRYPTED PRIVATE KEY-----',
    PEM_CERTIFICATE: '-----BEGIN CERTIFICATE-----',
    PKCS7_CERTIFICATE: '-----BEGIN PKCS7-----',
    PKCS10_CERTIFICATE: '-----BEGIN PKCS10-----',
    PKCS11_CERTIFICATE: '-----BEGIN PKCS11-----',
    PKCS12_CERTIFICATE: '-----BEGIN PKCS12-----',

    SHEBANG: [0x23, 0x21],
    MZ: [0x4D, 0x5A],

    PRIVATE_KEY_512: [0x30, 0x82, 0x01],
    PRIVATE_KEY_1024: [0x30, 0x82, 0x02],
    PRIVATE_KEY_2048: [0x30, 0x82, 0x04],
    PRIVATE_KEY_4096: [0x30, 0x82, 0x09],
    DER_FILE: [0x30, 0x82],

    //PVK: [] //http://justsolve.archiveteam.org/wiki/PVK

    ISO: [0x43, 0x44, 0x30, 0x30, 0x31], //ISO9660 CD/DVD image file

    RAR_150: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00], //Roshal ARchive compressed archive v1.50 onwards
    RAR_500: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00], //Roshal ARchive compressed archive v5.00 onwards

    ZIP_FILE: [0x50, 0x4b, 0x03, 0x04],
    ZIP_FILE_EMPTY: [0x50, 0x4b, 0x03, 0x06],
    ZIP_FILE_SPANNED: [0x50, 0x4b, 0x03, 0x08],

    XML: '<?xml'
};