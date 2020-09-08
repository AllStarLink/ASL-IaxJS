'use strict'

require('dotenv').config()
const Server = require('./lib/Server.js');
const RegisterApi = require('./lib/RegisterApi.js');
const _ = require('lodash');

Server.init(Iax.receiveMessage);

const Iax = {
    calls: [],
    CMD: {
        PING: 2,
        PONG: 3,
        ACK: 4,
        LAGRQ: 11,
        LAGRP: 12,
        REGREQ: 13,
        REGAUTH: 14,
        REGACK: 15,
        REGREJ: 16,
        REGREL: 17,
        POKE: 30,
        CALLTOKEN: 40
    },
    IE: {
        USERNAME: 6,
        PASSWORD: 7,
        AUTHMETHODS: 14,
        MD5CHALLENGE: 15,
        MD5CHALLENGERESP: 16,
        PEERADDRESS: 18,
        REFRESH: 19,
        CAUSE: 22,
        DATETIME: 31,
        CAUSECODE: 42,
        CALLTOKEN: 54
    },
    receiveMessage(msg, info) {
        console.log('Received %d bytes from %s:%d\n', msg.length, info.address, info.port);
        console.log(msg.toString('hex'));

        let parsed = {}
        parsed.scall = this.clearBit(msg.readUIntBE(0, 2));
        parsed.dcall = this.clearBit(msg.readUIntBE(2, 2));
        parsed.timeStamp = msg.readUIntBE(4, 4);
        parsed.outboundSeqNo = msg.readUIntBE(8, 1);
        parsed.inboundSeqNo = msg.readUIntBE(9, 1);
        parsed.cmdType = msg.readUIntBE(11, 1);

        // console.log('Source Call:', parsed.scall);
        // console.log('Dest Call:', parsed.dcall);
        console.log('Timestamp:', parsed.timeStamp);
        // console.log('Outbound Seq No:', parsed.outboundSeqNo);
        // console.log('Inbound Seq No:', parsed.inboundSeqNo);
        console.log('CMD:', this.getCmdType(parsed.cmdType) || "UNKNOWN");

        // Information elements
        let infoElements = [];
        this.parseInfoElements(msg.slice(12), infoElements);
        parsed.infoElements = infoElements;

        // Look to see if there's an existing entry for this call
        parsed.call = this.retrieveCall(parsed);

        switch (parsed.cmdType) {
            case this.CMD.REGREL:
                // TODO
                this.regReleaseResponse(parsed, info);
                break;
            case this.CMD.REGREQ:
                this.processRegRequest(parsed, info);
                break;
            case this.CMD.PING:
            case this.CMD.POKE:
                this.pongResponse(parsed, info);
                break;
            case this.CMD.LAGRQ:
                this.lagResponse(parsed, info);
            default:
                // Just ignore them
                break;
        }
    },
    processRegRequest(inMsg, senderInfo) {
        let verifyRegReq = false;
        /*
            Check to see if this is an initial REGREQ, or an MD5 salted one.
            The first request from Asterisk is REGREQ, which the server responds
            with an MD5 challenge. Asterisk then adds the challenge to the beginning
            of the password, hashes it again, and does another REGREQ.
         */
        _.each(inMsg.infoElements, (v) => {
            if (v.type === this.IE.MD5CHALLENGERESP) {
                verifyRegReq = true;
            }
        });

        // Authenticate with the MD5 challenge hashed password against our DB
        if (verifyRegReq) {
            console.log("#!?!?!?! VERIFYREGREQUEST ?!?!?!?!?");
            return this.verifyRegRequest(inMsg, senderInfo);
        }

        this.regRequestResponse(inMsg, senderInfo);
    },
    regRequestResponse(inMsg, senderInfo) {
        let sourceDestArr = new Uint16Array([
            // Turns this into 0x8001. This would normally be easy but JS doesn't have strong typing
            // or I'm stupid
            inMsg.call.dst,
            // FIXME
            // this.addBitwise(32768, this.generateRandomNumber(1, 65534)), 
            inMsg.call.src,
            0,
            1
        ]);

        let buffer = Buffer.from(sourceDestArr.buffer).swap16(); // Swap for Endian
        let randomChallenge = this.generateRandomNumber(100000000, 999999999);
        let username = this.getNode(inMsg.infoElements);

        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.REGAUTH,
            // IE Begin
            this.IE.AUTHMETHODS,
            2, // Length of Auth Method
            0, // Auth method
            3, // Auth method
            this.IE.MD5CHALLENGE,
            9, // MD5 Challenge length
            ...Buffer.from(String(randomChallenge)),
            this.IE.USERNAME,
            username.length,
            ...Buffer.from(String(username))
        ]);

        let outMsgBuf = Buffer.concat([buffer, outMsg]);
        Server.send(outMsgBuf, senderInfo.address, senderInfo.port);
    },
    verifyRegRequest(inMsg, senderInfo) {
        let sourceDestArr = new Uint16Array([
            inMsg.call.dest,
            inMsg.call.src,
            0,
            1
        ]);

        let buffer = Buffer.from(sourceDestArr.buffer).swap16(); // Swap for Endian
        let username = this.getNode(inMsg.infoElements);

        // Parse IP for sending back PEERADDRESS
        let ipArr = senderInfo.address.match(/(\d{1,3})/g);

        let testArr = [
            inMsg.call.outboundSeqNo,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.REGACK,
            // IE Begin
            this.IE.USERNAME,
            username.length,
            ...Buffer.from(String(username)),
            this.IE.DATETIME,
            4, // Length
            // DateTime START
            0x29,
            0x27,
            0x06,
            0x93,
            // DateTime END
            this.IE.REFRESH,
            2, // Length
            0, // REFRESH time
            5, // REFRESH time
            this.IE.PEERADDRESS,
            16, // Length
            ...[0x02, 0x00], // Family FIXME
            ...this.splitIntToByteArray(senderInfo.port),
            ...ipArr, // Client's IP
            // Padding probably for IPv6
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ];

        let outMsg = new Uint8Array(testArr);
        console.log(outMsg);
        let outMsgBuf = Buffer.concat([buffer, Buffer.from(outMsg)]);
        console.log(outMsgBuf.toString('hex'));
        Server.send(outMsgBuf, senderInfo.address, senderInfo.port);

    },
    regReleaseResponse(inMsg, senderInfo) {
        let sourceDestArr = new Uint16Array([
            inMsg.call.dest,
            inMsg.call.src,
            0,
            1
        ]);

        let buffer = Buffer.from(sourceDestArr.buffer).swap16(); // Swap for Endian

        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.PONG,
        ]);

        let outMsgBuf = Buffer.concat([buffer, Buffer.from(outMsg)]);
        Server.send(outMsgBuf, senderInfo.address, senderInfo.port);
    },
    /**
     * This command only needs the CMD and nothing else to respond
     *
     * @param inMsg
     * @param senderInfo
     */
    pongResponse(inMsg, senderInfo) {
        let sourceDestArr = new Uint16Array([
            inMsg.call.dest,
            inMsg.call.src,
            0,
            1
        ]);

        let buffer = Buffer.from(sourceDestArr.buffer).swap16(); // Swap for Endian

        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.PONG,
        ]);

        let outMsgBuf = Buffer.concat([buffer, Buffer.from(outMsg)]);
        Server.send(outMsgBuf, senderInfo.address, senderInfo.port);
    },
    /**
     * This command differs slightly from PONG, in that it needs the timestamp from the client repeated back
     * @param inMsg
     * @param senderInfo
     */
    lagResponse(inMsg, senderInfo) {
        let sourceDestArr = new Uint16Array([
            inMsg.call.dest,
            inMsg.call.src,
        ]);

        let tArr = new Uint32Array([inMsg.timeStamp]);
        let buffer = Buffer.from(sourceDestArr.buffer).swap16(); // Swap for Endian
        let tBuffer = Buffer.from(tArr.buffer).swap32(); // Swap for Endian

        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.LAGRP,
        ]);

        let outMsgBuf = Buffer.concat([buffer, tBuffer, Buffer.from(outMsg)]);
        Server.send(outMsgBuf, senderInfo.address, senderInfo.port);
    },
    parseInfoElements(buffer, infoElements) {
        if (!buffer.length) return false;

        let type = buffer.readUIntBE(0, 1);
        let length = buffer.readUIntBE(1, 1);
        let data = buffer.slice(2, 2 + length);

        infoElements.push({
            type: type,
            data: data
        });

        type = this.getInfoType(type);
        console.log("Info Type", type || 'UNKNOWN');
        console.log("Length", length);
        console.log("Data");

        if (type === 19) {
            console.log(data.readUInt16BE(0));
        } else {
            console.log(data.toString());
        }

        buffer = buffer.slice(2 + length);
        this.parseInfoElements(buffer, infoElements);
    },
    getNode(infoElements) {
        let node = null;

        _.each(infoElements, (v) => {
            if (v.type !== this.IE.USERNAME) return;
            node = v.data;
        });

        return node;
    },
    getCmdType(type) {
        let cmdType = null;

        _.each(this.CMD, (v, k) => {
            if (v !== type) return;
            cmdType = k;
        })

        return cmdType;
    },
    getInfoType(type) {
        let infoType = null;

        _.each(this.IE, (v, k) => {
            if (v !== type) return;
            infoType = k;
        })

        return infoType;
    },
    retrieveCall(parsed) {

    },
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
    subtractBitwise(a, b) {
        return addBitwise(a, b, true)
    },
    generateRandomNumber(min, max) {
        return Math.floor(Math.random() * (max - min) + min);
    },
    clearBit(n) {
        return (n ^ (1 << 15));
    },
    splitIntToByteArray(input) {
        return input
            .toString(16)
            .match(/.{1,2}/g)
            .map(b => parseInt(b.padStart(4, '0x')));
    },
    bufferToHex(buffer) {
        return [...new Uint8Array(buffer)]
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
    }
};

module.exports = Iax;

