export declare class Storage {
    private storage;
    constructor();
    setStorage: (storage: any) => void;
    setItem: (key: string, value: string, expiresIn?: number) => Promise<boolean>;
    getItem: (key: string) => Promise<any>;
}
declare const _default: Storage;
export default _default;
