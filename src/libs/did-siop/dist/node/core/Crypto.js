"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Crypto = void 0;
var hashUtils = __importStar(require("hash.js"));
var pbkdf2 = require('pbkdf2');
var aesjs = require('aes-js');
var aes_salt = 'EpOcWe6ulTd1pKI2fsywukZCwwpVJF1c';
/**
 * @classdesc This class provides the functionality of encryption and decryption
 */
var Crypto = /** @class */ (function () {
    function Crypto() {
        var _this = this;
        this.ivArray = [];
        this.keyArray = [];
        this.init = function (password) {
            _this.ivArray = _this.pbkdf2(password, aes_salt, 16);
            _this.keyArray = _this.pbkdf2(aesjs.utils.hex.fromBytes(_this.ivArray), aes_salt, 32);
            return { a: _this.ivArray, b: _this.keyArray };
        };
        this.encrypt = function (textToEncrypt) {
            var textBytes = aesjs.utils.utf8.toBytes(textToEncrypt);
            var aesCbc = new aesjs.ModeOfOperation.cbc(_this.keyArray, _this.ivArray);
            var encryptedBytes = aesCbc.encrypt(aesjs.padding.pkcs7.pad(textBytes));
            var encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
            return encryptedHex;
        };
        this.decrypt = function (encryptedText) {
            var encryptedBytes = aesjs.utils.hex.toBytes(encryptedText);
            var aesCbc = new aesjs.ModeOfOperation.cbc(_this.keyArray, _this.ivArray);
            var decryptedBytes = aesCbc.decrypt(encryptedBytes);
            var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
            return decryptedText;
        };
        this.pbkdf2 = function (password, salt, keySize) {
            var iterations = 4096;
            var keyInBytes = keySize;
            var hash = "sha256";
            var passwordKey = pbkdf2.pbkdf2Sync(password, salt, iterations, keyInBytes, hash);
            return passwordKey;
        };
    }
    Crypto.hash = function (value) {
        var sha256 = hashUtils.sha256();
        var level1 = sha256.update(value).digest('hex');
        var salted = level1 + aes_salt;
        var level2 = sha256.update(salted).digest('hex');
        var result = sha256.update(level2).digest('hex');
        return result;
    };
    return Crypto;
}());
exports.Crypto = Crypto;
//# sourceMappingURL=Crypto.js.map