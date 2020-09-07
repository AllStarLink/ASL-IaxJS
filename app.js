'use strict'

const Server = require('./lib/server.js');
const server = Server.init();
const _ = require('lodash');

// emits on new datagram msg
server.on('message', function (msg, info) {
    Iax.receiveMessage(msg, info);
});

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
        CALLTOKEN: 0x28
    },
    IE: {
        USERNAME: 6,
        PASSWORD: 7,
        AUTHMETHODS: 14,
        MD5CHALLENGE: 15,
        MD5CHALLENGERESP: 16,
        PEERADDRESS: 18,
        REFRESH: 19,
        DATETIME: 31,
        CALLTOKEN: 0x36
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
        console.log('CMD:', this.getCmdType(parsed.cmdType));

        // Information elements
        let infoElements = [];
        this.parseInfoElements(msg.slice(12), infoElements);
        parsed.infoElements = infoElements;

        switch (parsed.cmdType) {
            case this.CMD.REGREQ:
                this.processRegRequest(parsed, info);
                break;
            case this.CMD.PING:
                this.pongResponse(parsed, info);
                break;
            case this.CMD.LAGRQ:
                this.lagResponse(parsed, info);
            default:
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
            this.addBitwise(32768, this.generateRandomNumber(1000,2000)),
            inMsg.scall,
            0,
            1
        ]);

        let buffer = Buffer.from(sourceDestArr.buffer).swap16();

        let randomChallenge = this.generateRandomNumber(100000000,999999999);
        let username = this.getNode(inMsg.infoElements);
        
        let outMsg = new Uint8Array([
            0,
            1, // (++inMsg.inboundSeqNo),
            6, // IAX
            Iax.CMD.REGAUTH,
            Iax.IE.AUTHMETHODS,
            2, // Length of Auth Method
            0, // Auth method
            3, // Auth method
            Iax.IE.MD5CHALLENGE,
            9,
            // Random # begin
            ...Buffer.from(String(randomChallenge)),
            6,
            username.length,
            ...Buffer.from(String(username))
        ]);

        let outMsgBuf = Buffer.concat([buffer, outMsg]);
        Server.send(outMsgBuf, senderInfo.address, senderInfo.port);
    },
    verifyRegRequest(inMsg, senderInfo) {
        let sourceDestArr = new Uint16Array([
            inMsg.dcall,
            inMsg.scall,
            0,
            1
        ]);

        let buffer = Buffer.from(sourceDestArr.buffer).swap16();
        let username = this.getNode(inMsg.infoElements);

        // Parse IP for sending back PEERADDRESS
        let ipArr = senderInfo.address.match(/(\d{1,3})/g);
        
        let testArr = [
            (inMsg.inboundSeqNo),
            (++inMsg.outboundSeqNo),
            6, // IAX
            this.CMD.REGACK,
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
            0x00,
            5, // REFRESH TIME
            this.IE.PEERADDRESS,
            16, // Length
            2, // Family?
            0,
            ...this.splitIntToByteArray(senderInfo.port),
            ...ipArr,
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
    pongResponse(inMsg, senderInfo) {
        let sourceDestArr = new Uint16Array([
            inMsg.dcall,
            inMsg.scall,
            0,
            1
        ]);

        let buffer = Buffer.from(sourceDestArr.buffer).swap16();

        let outMsg = new Uint8Array([
            (inMsg.inboundSeqNo),
            (++inMsg.outboundSeqNo),
            6,
            Iax.CMD.PONG,
        ]);

        let outMsgBuf = Buffer.concat([buffer, Buffer.from(outMsg)]);
        Server.send(outMsgBuf, senderInfo.address, senderInfo.port);
    },
    lagResponse(inMsg, senderInfo) {
        let sourceDestArr = new Uint16Array([
            inMsg.dcall,
            inMsg.scall,
        ]);

        let tArr = new Uint32Array([inMsg.timeStamp]);
        let buffer = Buffer.from(sourceDestArr.buffer).swap16();
        let tBuffer = Buffer.from(tArr.buffer).swap32();

        let outMsg = new Uint8Array([
            (++inMsg.inboundSeqNo),
            (++inMsg.outboundSeqNo),
            6,
            Iax.CMD.LAGRP,
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
        console.log("Info Type", type);
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
            if (v.type !== this.IE.USERNAME) return null;
            node = v.data;
        });
        
        return node;
    },
    getCmdType(type) {
        let cmdType = 'UNKNOWN';

        _.each(this.CMD, (v, k) => {
            if (v !== type) return;
            cmdType = k;
        })

        return cmdType;
    },
    getInfoType(type) {
        let infoType = 'UNKNOWN';

        _.each(this.IE, (v, k) => {
            if (v !== type) return;
            infoType = k;
        })

        return infoType;
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
    bufferToHex (buffer) {
        return [...new Uint8Array (buffer)]
            .map (b => b.toString (16).padStart (2, "0"))
            .join ("");
    }
};

module.exports = Iax;

