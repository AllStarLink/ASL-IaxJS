'use strict'

require('dotenv').config();

const Server = require('./lib/Server.js');
const RegisterApi = require('./lib/RegisterApi.js');
const Util = require('./lib/Util.js');
const Call = require('./lib/Call.js');

const _ = require('lodash');
const colors = require('colors');

const Iax = {
    CMD: {
        PING: 2,
        PONG: 3,
        ACK: 4,
        INVAL: 10,
        LAGRQ: 11,
        LAGRP: 12,
        REGREQ: 13,
        REGAUTH: 14,
        REGACK: 15,
        REGREJ: 16,
        REGREL: 17,
        VNAK: 18,
        POKE: 30,
        CALLTOKEN: 40,
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
        CALLTOKEN: 54,
    },
    receiveMessage(msg, info) {
        console.log("##############################################".blue);
        console.log('Received %d bytes from %s:%d', msg.length, info.address, info.port);
        // console.log(msg.toString('hex'));

        let inMsg = {}
        inMsg.scall = Util.clearBit(msg.readUIntBE(0, 2));
        let dcall = msg.readUIntBE(2, 2);
        inMsg.dcall = Util.clearBit(dcall);
        inMsg.retransmit = false;

        // Check for re-transmission
        if (dcall & (1 << 15)) {
            inMsg.retransmit = true;
            console.log(`Retransmit? ${inMsg.dcall}`.bold.underline.magenta);
        }

        inMsg.timeStamp = msg.readUIntBE(4, 4);
        inMsg.outboundSeqNo = msg.readUIntBE(8, 1);
        inMsg.inboundSeqNo = msg.readUIntBE(9, 1);
        inMsg.cmdType = msg.readUIntBE(11, 1);

        console.log('Source Call:', String(inMsg.scall).yellow);
        console.log('Dest Call:', String(inMsg.dcall).yellow);
        // console.log('Timestamp:', inMsg.timeStamp);
        console.log('Outbound Seq No:', inMsg.outboundSeqNo);
        console.log('Inbound Seq No:', inMsg.inboundSeqNo);
        console.log('CMD:', (this.getCmdType(inMsg.cmdType) || "UNKNOWN").green);

        // Information elements
        let infoElements = [];
        this.parseInfoElements(msg.slice(12), infoElements);
        inMsg.infoElements = infoElements;
        inMsg.senderInfo = info;

        // Look to see if there's an existing entry for this call
        inMsg.call = Call.retrieveCall(inMsg);

        if (inMsg.retransmit) {
            this.lagOrAckResponse(inMsg, true);
        }
        
        if (!inMsg.call.new && [this.CMD.VNAK].indexOf(inMsg.cmdType) !== -1) {
            --inMsg.call.inboundSeqNo;
        }

        switch (inMsg.cmdType) {
            case this.CMD.REGREQ:
            case this.CMD.REGREL:
                this.processRegRequest(inMsg);
                break;
            case this.CMD.PING:
            case this.CMD.POKE:
                this.pongResponse(inMsg);
                break;
            case this.CMD.LAGRQ:
                this.lagOrAckResponse(inMsg);
                break;
            case this.CMD.ACK:
                this.receiveAck(inMsg);
                break;
            case this.CMD.VNAK:
                this.receiveVnak(inMsg);
                break;
            default:
                // Just ignore them
                break;
        }

        console.log('##############################################'.blue);
    },
    processRegRequest(inMsg) {
        let challengeResponse = false;
        let node = null;

        /*
            Check to see if this is an initial REGREQ, or an MD5 salted one.
            The first request from Asterisk is REGREQ, which the server responds
            with an MD5 challenge. Asterisk then adds the challenge to the beginning
            of the password, hashes it again, and does another REGREQ.
         */
        _.each(inMsg.infoElements, (v) => {
            if (v.type === this.IE.MD5CHALLENGERESP) {
                challengeResponse = v.data;
            } else if (v.type === this.IE.USERNAME) {
                node = v.data;
            }
        });

        // Authenticate with the MD5 challenge hashed password against our DB
        if (challengeResponse) {
            console.log("?!?!?!?!?!?!?! VERIFYREGREQUEST ?!?!?!?!?!?!?!");
            return this.verifyRegRequest(inMsg, node, challengeResponse);
        }

        this.regRequestResponse(inMsg);
    },
    regRequestResponse(inMsg) {
        let buffer = this.getSourceDestBuf(inMsg);
        let tBuffer = this.getTimeStampBuf(inMsg.call.timeStamp);
        let randomChallenge = Util.generateRandomNumber(100000000, 999999999);
        let username = this.getNode(inMsg.infoElements);

        inMsg.call.challenge = randomChallenge;

        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo++,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.REGAUTH,
            // IE Begin
            this.IE.AUTHMETHODS,
            2, // Length of Auth Method
            0, // Auth method
            2, // Auth method
            this.IE.MD5CHALLENGE,
            9, // MD5 Challenge length
            ...Buffer.from(String(randomChallenge)),
            this.IE.USERNAME,
            username.length,
            ...Buffer.from(String(username))
        ]);

        let outMsgBuf = Buffer.concat([buffer, tBuffer, outMsg]);
        Server.send(outMsgBuf, inMsg.senderInfo.address, inMsg.senderInfo.port);
    },
    async verifyRegRequest(inMsg, node, challengeResponse) {
        // May refactor in the future
        if (inMsg.cmdType === this.CMD.REGREQ) {
            if (await RegisterApi.register(node, inMsg.call.challenge, challengeResponse.toString(), inMsg.senderInfo.address, inMsg.senderInfo.port)) {
                return this.regAckResponse(inMsg);
            }
        } else if (inMsg.cmdType === this.CMD.REGREL) {
            if (await RegisterApi.unregister(node, inMsg.call.challenge, challengeResponse.toString(), inMsg.senderInfo.address, inMsg.senderInfo.port)) {
                return this.regReleaseResponse(inMsg);
            }
        }

        return this.regRejectResponse(inMsg);
    },
    regAckResponse(inMsg) {
        let buffer = this.getSourceDestBuf(inMsg);
        let tBuffer = this.getTimeStampBuf(inMsg.call.timeStamp);
        let username = this.getNode(inMsg.infoElements);

        // Parse IP for sending back PEERADDRESS
        let ipArr = inMsg.senderInfo.address.match(/(\d{1,3})/g);

        let testArr = [
            inMsg.call.outboundSeqNo++,
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
            process.env.CLIENT_REFRESH_TIME, // REFRESH time
            this.IE.PEERADDRESS,
            16, // Length
            ...[0x02, 0x00], // Family FIXME
            ...Util.splitIntToByteArray(inMsg.senderInfo.port),
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
        let outMsgBuf = Buffer.concat([buffer, tBuffer, Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo.address, inMsg.senderInfo.port);
        console.log(`Registered node ${username} at ${inMsg.senderInfo.address}:${inMsg.senderInfo.port}`.magenta);
    },
    regRejectResponse(inMsg) {
        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo++,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.REGREJ,
            this.IE.CAUSE,
            18, // Length of string below
            ...Buffer.from('Password incorrect'),
            this.IE.CAUSECODE,
            1, // Length
            0x1D // Facility Rejected
        ]);
        
        let outMsgBuf = Buffer.concat([this.getResponseBuf(inMsg), Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo.address, inMsg.senderInfo.port);
        let username = this.getNode(inMsg.infoElements);
        console.log(`Auth rejected for node ${username} at ${inMsg.senderInfo.address}:${inMsg.senderInfo.port}`.magenta);
    },
    regReleaseResponse(inMsg) {
        return this.lagOrAckResponse(inMsg, true, false);
    },
    /**
     * This command only needs the CMD and nothing else to respond
     *
     * @param inMsg
     * @param inMsg.senderInfo
     */
    pongResponse(inMsg) {
        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo++,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.PONG,
        ]);

        let outMsgBuf = Buffer.concat([this.getResponseBuf(inMsg, true), Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo.address, inMsg.senderInfo.port);
        Call.deleteCall(inMsg);
    },
    /**
     * This command differs slightly from PONG, in that it needs the timestamp from the client repeated back
     * @param inMsg
     * @param inMsg.senderInfo
     */
    lagOrAckResponse(inMsg, ack = false, resetCallSeq = true) {
        // Not sure if this is the best approach. May refactor later.
        if (ack && resetCallSeq) {
            Call.resetCallSeq(inMsg);
        } 

        let outMsg = new Uint8Array([
            inMsg.outboundSeqNo,
            inMsg.inboundSeqNo,
            6, // IAX
            (ack ? this.CMD.ACK : this.CMD.LAGRP)
        ]);

        let outMsgBuf = Buffer.concat([this.getResponseBuf(inMsg, true), Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo.address, inMsg.senderInfo.port);
    },
    invalResponse(inMsg) {
        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo,
            inMsg.call.inboundSeqNo,
            6,
            this.CMD.INVAL
        ])
        
        let outMsgBuf = Buffer.concat([this.getResponseBuf(inMsg, true), Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo.address, inMsg.senderInfo.port);
        console.error(`INVAL Sent to ${inMsg.call.scall}`.bgRed.white);
        Call.deleteCall(inMsg);
    },
    receiveAck(inMsg) {
        if (!inMsg.call.new) {
            Call.deleteCall(inMsg);
            return true;
        }

        console.error(inMsg.call);
    },
    receiveVnak(inMsg) {
        Call.resetCallSeq(inMsg);
        this.invalResponse(inMsg);
    },
    getResponseBuf(inMsg, sendTheirTimestamp = false) {
        return Buffer.concat([
            this.getSourceDestBuf(inMsg),
            this.getTimeStampBuf(sendTheirTimestamp ? inMsg.timeStamp : inMsg.call.timeStamp)
        ]);
    },
    getSourceDestBuf(inMsg) {
        let sourceDestArr = new Uint16Array([
            Util.checkAndSetBit(inMsg.call.dcall),
            inMsg.call.scall,
        ]);

        return Buffer.from(sourceDestArr.buffer).swap16();
    },
    getTimeStampBuf(timeStamp) {
        let tArr = new Uint32Array([timeStamp]);
        return Buffer.from(tArr.buffer).swap32(); // Swap for Endian
    },
    parseInfoElements(buffer, infoElements) {
        if (!buffer.length) return false;

        try {
            let type = buffer.readUIntBE(0, 1);
            let length = buffer.readUIntBE(1, 1);
            let data = buffer.slice(2, 2 + length);

            infoElements.push({
                type: type,
                data: data
            });

            let typeStr = this.getInfoType(type);

            if (type !== this.IE.REFRESH && type !== this.IE.CALLTOKEN) {
                console.log("Info Type", (typeStr || 'UNKNOWN').green);
                console.log("Length", length.toString().yellow);
                console.log("Data");
                console.log(data.toString().green);
            }

            buffer = buffer.slice(2 + length);
            this.parseInfoElements(buffer, infoElements);
        } catch (e) {
            console.error(e);
        }
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
    }
};

Server.init((msg, info) => {
    try {
        Iax.receiveMessage(msg, info);
    } catch (e) {
        console.error(e);
    }
});

setInterval(() => {
    Call.pruneCalls();
}, 5000)
