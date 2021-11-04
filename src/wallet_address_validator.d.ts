
declare module 'trezor-address-validator' {
    export interface Currency {
        name: string,
        symbol: string,
    };
    export type AddressType = 'address' | 'pkh' | 'wpkh' | 'wsh' | 'sh-wpkh' | 'tr' | 'witness-unknown';
    export function validate(address: string, currencyNameOrSymbol?: string, networkType?: string): boolean;
    export function getAddressType(address: string, currencyNameOrSymbol?: string, networkType?: string): AddressType | undefined;
    export function getCurrencies(): Currency[];
    export function findCurrency(symbol: string): Currency
}

