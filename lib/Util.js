/**
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license GPL-3.0-only
 */
const Util = {
    /**
     * 
     * @param a
     * @param b
     * @param subtract
     * @returns {*}
     */
    addBitwise(a, b, subtract = false) {
        while (b !== 0) {
            let borrow;
            if (subtract) borrow = (~a) & b;
            else borrow = a & b;
            a = a ^ b;
            b = borrow << 1;
        }

        return a;
    },
    /**
     * 
     * @param a
     * @param b
     * @returns {number}
     */
    subtractBitwise(a, b) {
        return this.addBitwise(a, b, true)
    },
    /**
     * 
     * @param min
     * @param max
     * @returns {number}
     */
    generateRandomNumber(min, max) {
        return Math.floor(Math.random() * (max - min) + min);
    },
    /**
     * 
     * @param n
     * @returns {number|*}
     */
    clearBit(n) {
        return n > 0 ? (n ^ (1 << 15)) : n;
    },
    /**
     * 
     * @param n
     * @returns {*|number}
     */
    checkAndSetBit(n) {
        return (n & (1 << 15)) === 32768 ? n : (n | 1 << 15);
    },
    /**
     * 
     * @param input
     * @returns {number[]}
     */
    splitIntToByteArray(input) {
        return input
            .toString(16)
            .match(/.{1,2}/g)
            .map(b => parseInt(b.padStart(4, '0x')));
    },
    /**
     * 
     * @param buffer
     * @returns {string}
     */
    bufferToHex(buffer) {
        return [...new Uint8Array(buffer)]
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
    },
    /**
     * 
     * @param ms
     * @returns {Promise<unknown>}
     */
    timeout(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

module.exports = Util;