/**
 * @classdesc This class provides the functionality of encryption and decryption
 */
export declare class Crypto {
    private ivArray;
    private keyArray;
    init: (password: string) => {
        a: any;
        b: any;
    };
    encrypt: (textToEncrypt: string) => string;
    decrypt: (encryptedText: string[] | string | null | undefined) => string;
    pbkdf2: (password: string, salt: string, keySize: number) => any;
    static hash: (value: string) => string;
}
