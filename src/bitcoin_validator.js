const { bech32, bech32m } = require('bech32');
var base58 = require('./crypto/base58');
var segwit = require('./crypto/segwit_addr');
var cryptoUtils = require('./crypto/utils');

var DEFAULT_NETWORK_TYPE = 'prod';

function getDecoded(address) {
    try {
        return base58.decode(address);
    } catch (e) {
        // if decoding fails, assume invalid address
        return null;
    }
}

function getChecksum(hashFunction, payload) {
    // Each currency may implement different hashing algorithm
    switch (hashFunction) {
        // blake then keccak hash chain
        case 'blake256keccak256':
            var blake = cryptoUtils.blake2b256(payload);
            return cryptoUtils.keccak256Checksum(Buffer.from(blake, 'hex'));
        case 'blake256':
            return cryptoUtils.blake256Checksum(payload);
        case 'keccak256':
            return cryptoUtils.keccak256Checksum(payload);
        case 'groestl512x2':
            return cryptoUtils.groestl512x2(payload);
        case 'sha256':
        default:
            return cryptoUtils.sha256Checksum(payload);
    }
}

function getAddressType(address, currency) {
    currency = currency || {};
    // should be 25 bytes per btc address spec and 26 decred
    var expectedLength = currency.expectedLength || 25;
    var hashFunction = currency.hashFunction || 'sha256';
    var decoded = getDecoded(address);

    if (decoded) {
        var length = decoded.length;

        if (length !== expectedLength) {
            return null;
        }

        if(currency.regex) {
            if(!currency.regex.test(address)) {
                return null;
            }
        }

        var checksum = cryptoUtils.toHex(decoded.slice(length - 4, length)),
            body = cryptoUtils.toHex(decoded.slice(0, length - 4)),
            goodChecksum = getChecksum(hashFunction, body);

        return checksum === goodChecksum ? cryptoUtils.toHex(decoded.slice(0, expectedLength - 24)) : null;
    }

    return null;
}

function getOutputIndex(address, currency, networkType) {
    let correctAddressTypes;
    const addressType = getAddressType(address, currency);
    if (addressType) {
        if (networkType === 'prod' || networkType === 'testnet') {
            correctAddressTypes = currency.addressTypes[networkType]
        } else {
            correctAddressTypes = currency.addressTypes.prod.concat(currency.addressTypes.testnet);
        }
        return correctAddressTypes.indexOf(addressType);
    }
    return null;
}

function isValidPayToPublicKeyHashAddress(address, currency, networkType) {
    return getOutputIndex(address, currency, networkType) === 0;
}

function isValidPayToScriptHashAddress(address, currency, networkType) {
    return getOutputIndex(address, currency, networkType) > 0;
}

function isValidPayToWitnessScriptHashAddress(address) {
    try {
        const decoded = bech32.decode(address);
        const version = decoded.words[0];
        return version === 0 && decoded.words.length - 1 === 52; // 52 characters for 32-byte witness programs like P2WSH or P2TR
    } catch (err) {
        return null;
    }
}

function isValidPayToWitnessPublicKeyHashAddress(address, currency) {
    try {
        const decoded = bech32.decode(address);
        const version = decoded.words[0];
        return version === 0 && decoded.words.length - 1 === 32; // 32 characters for 20-byte witness programs like P2WPKH
    } catch (err) {
        return null;
    }
}

function isValidPayToTaprootAddress(address) {
    let decoded = null;
    try {
        decoded = bech32m.decode(address);
    } catch (err) {
        return null;
    }
    const version = decoded.words[0];
    return version === 1;
}

function isValidWitnessUnknownAddress(address) {
    try {
        const decoded = bech32.decode(address);
        const version = decoded.words[0];
        return (
            version === 0 &&
            decoded.words.length - 1 !== 32 && // Not P2WSH or P2TR
            decoded.words.length - 1 !== 52 // Not P2WPKH
        );
    } catch (err) {
        try {
            const decoded = bech32m.decode(address);
            const version = decoded.words[0];
            return version > 1;
        } catch (err) {
            return null;
        }
    }
}

module.exports = {
    isValidAddress: function (address, currency, networkType) {        
        networkType = networkType || DEFAULT_NETWORK_TYPE;
        // return ['WITNESS_UNKNOWN', undefined].includes(this.getAddressType(address, currency, networkType)) === false;
        return (
            isValidPayToPublicKeyHashAddress(address, currency, networkType) ||
            isValidPayToScriptHashAddress(address, currency, networkType) ||
            segwit.isValidAddress(address, currency, networkType)
        ); // Is this correct?
    },
    getAddressType: function(address, currency, networkType) {
        networkType = networkType || DEFAULT_NETWORK_TYPE;
        if (isValidPayToPublicKeyHashAddress(address, currency, networkType)) {
            return 'P2PKH';
        }
        if (isValidPayToScriptHashAddress(address, currency, networkType)) {
            return 'P2SH';
        }
        if (isValidPayToWitnessScriptHashAddress(address)) {
            return 'P2WSH';
        }
        if (isValidPayToWitnessPublicKeyHashAddress(address)) {
            return 'P2WPKH';
        }
        if (isValidPayToTaprootAddress(address)) {
            return 'P2TR';
        }
        if (isValidWitnessUnknownAddress(address) || segwit.isValidAddress(address, currency, networkType)) {
            return 'WITNESS_UNKNOWN';
        }
        return undefined;
    },
};
