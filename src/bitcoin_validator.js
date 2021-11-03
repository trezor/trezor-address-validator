const { bech32, bech32m } = require('bech32');
var base58 = require('./crypto/base58');
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

function convertbits(data, frombits, tobits, pad) {
  var acc = 0;
  var bits = 0;
  var ret = [];
  var maxv = (1 << tobits) - 1;
  for (var p = 0; p < data.length; ++p) {
    var value = data[p];
    if (value < 0 || (value >> frombits) !== 0) {
      return null;
    }
    acc = (acc << frombits) | value;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      ret.push((acc << (tobits - bits)) & maxv);
    }
  } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
    return null;
  }
  return ret;
}

function decodeBech32(hrp, addr, m = false) {
    var dec;
    try {
        if (m) {
            dec = bech32m.decode(addr);
        } else {
            dec = bech32.decode(addr);
        }
    } catch (err) {
        return null;
    }
    const version = dec?.words[0];
    if (
        dec === null ||
        dec.prefix !== hrp ||
        dec.words.length < 1 ||
        version > 16
    ) {
        return null;
    }
    var res = convertbits(dec.words.slice(1), 5, 8, false);
    if (res === null || res.length < 2 || res.length > 40) {
        return null;
    }
    return { version, program: res };
}

function isValidPayToPublicKeyHashAddress(address, currency, networkType) {
    return getOutputIndex(address, currency, networkType) === 0;
}

function isValidPayToScriptHashAddress(address, currency, networkType) {
    return getOutputIndex(address, currency, networkType) > 0;
}

function isValidPayToWitnessScriptHashAddress(address, currency, networkType) {
    try {
        const hrp = currency.segwitHrp[networkType];
        const decoded = decodeBech32(hrp, address);
        return decoded.version === 0 && decoded.program.length === 32;
    } catch (err) {
        return null;
    }
}

function isValidPayToWitnessPublicKeyHashAddress(address, currency, networkType) {
    try {
        const hrp = currency.segwitHrp[networkType];
        const decoded = decodeBech32(hrp, address);
        return decoded.version === 0 && decoded.program.length === 20;
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

function decode(hrp, addr, m = false) {
    let dec;
    try {
        if (m) {
            dec = bech32m.decode(addr);
        } else {
            dec = bech32.decode(addr);
        }
    } catch (err) {
        return null;
    }
    const version = dec?.words[0];
    if (
        dec === null ||
        dec.prefix !== hrp ||
        dec.words.length < 1 ||
        version > 16
    ) {
        return null;
    }
    var res = convertbits(dec.words.slice(1), 5, 8, false);
    if (res === null || res.length < 2 || res.length > 40) {
        return null;
    }
    return { version, program: res };
}

function encode(hrp, version, program, m = false) {
    var ret;
    if (m) {
        ret = bech32m.encode(hrp, [version].concat(convertbits(program, 8, 5, true)));
    } else {
        ret = bech32.encode( hrp, [version].concat(convertbits(program, 8, 5, true)));
    }
    if (decode(hrp, ret, m) === null) {
        return null;
    }
    return ret;
}

function isValidAddress(address, currency, networkType, m = false) {
    if (!currency.segwitHrp) {
        return false;
    }
    var hrp = currency.segwitHrp[networkType];
    if (!hrp) {
        return false;
    }
    var ret = decode(hrp, address, m);
    if (ret === null) {
        return false;
    }
    if (m) {
        // I don't get this, how it's not 'version > 1'?
        if (ret.version <= 1) {
            return false;
        }
    } else {
        if (ret.version === 0 && ret.program.length !== 20 && ret.program.length !== 32) {
            return false;
        }
    }
    return address.toLowerCase() === encode(hrp, ret.version, ret.program, m);
}

module.exports = {
    isValidAddress: function (address, currency, networkType) {        
        networkType = networkType || DEFAULT_NETWORK_TYPE;
        const addressType = this.getAddressType(address, currency, networkType);
        // Though WITNESS_UNKNOWN is a valid address, it's not spendable - so we mark it as invalid
        // return addressType !== undefined && addressType !== 'WITNESS_UNKNOWN';
        return addressType !== undefined;
    },
    getAddressType: function(address, currency, networkType) {
        networkType = networkType || DEFAULT_NETWORK_TYPE;
        if (isValidPayToPublicKeyHashAddress(address, currency, networkType)) {
            return 'P2PKH';
        }
        if (isValidPayToScriptHashAddress(address, currency, networkType)) {
            return 'P2SH';
        }
        if (isValidPayToWitnessScriptHashAddress(address, currency, networkType)) {
            return 'P2WSH';
        }
        if (isValidPayToWitnessPublicKeyHashAddress(address, currency, networkType)) {
            return 'P2WPKH';
        }
        if (isValidPayToTaprootAddress(address)) {
            return 'P2TR';
        }
        // bech32
        if (isValidAddress(address, currency, networkType)) {
            return 'WITNESS_UNKNOWN';
        }
        // bech32m
        if (isValidAddress(address, currency, networkType, true)) {
            return 'WITNESS_UNKNOWN';
        }
        return undefined;
    },
};
