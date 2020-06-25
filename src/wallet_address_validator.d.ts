declare module 'trezor-address-validator' {
    export interface Currency {
        name: string,
        symbol: string,
    }

    export function validate(address: string, currencyNameOrSymbol: string, networkType?: string): boolean;
    export function getCurrencies(): Currency[];
    export function findCurrency(symbol: string): Currency
}

