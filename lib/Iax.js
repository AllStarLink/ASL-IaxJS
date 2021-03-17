/**
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @author Jason VE3YCA
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license AGPL-3.0-or-later
 */
const { mod } = require('mathjs')

const Server = require('./Server');
const RegisterApi = require('./RegisterApi');
const Util = require('./Util');
const _ = require('lodash');
const Call = new (require('./Call'));
const {Address4} = require('ip-address');

class Iax {
    constructor() {
        this.Call = Call;
        /**
         * Packet CMDs
         * @type {{ACK: number, VNAK: number, REGACK: number, REGREQ: number, INVAL: number, PING: number, REGAUTH: number, REGREJ: number, LAGRQ: number, POKE: number, PONG: number, LAGRP: number, REGREL: number, CALLTOKEN: number}}
         */
        this.CMD = {
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
        }
        /**
         * Packet Information Elements
         * @type {{MD5CHALLENGE: number, MD5CHALLENGERESP: number, CAUSECODE: number, PASSWORD: number, DATETIME: number, REFRESH: number, AUTHMETHODS: number, CAUSE: number, USERNAME: number, PEERADDRESS: number, CALLTOKEN: number}}
         */
        this.IE = {
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
        }
    }

    /**
     * Receives raw UDP datagram and parses
     *
     * @param msg
     * @param info
     * @returns {Promise<{}>}
     */
    async receiveMessage(msg, info) {
        try {
            let inMsg = {}

            let scall = msg.readUIntBE(0, 2);
            inMsg.scall = Util.clearBit(scall);
            let dcall = msg.readUIntBE(2, 2);
            inMsg.dcall = Util.clearBit(dcall);
            inMsg.retransmit = false;

            // Check for re-transmission
            if (dcall & (1 << 15)) {
                inMsg.retransmit = true;
                // Log.debug(`[IN] RT? ${info.address} [${scall}:${dcall}] -> [${inMsg.scall}:${inMsg.dcall}]`.bold.underline.magenta);
            }

            inMsg.timeStamp = msg.readUIntBE(4, 4);
            inMsg.outboundSeqNo = msg.readUIntBE(8, 1);
            inMsg.inboundSeqNo = msg.readUIntBE(9, 1);
            inMsg.cmdType = msg.readUIntBE(11, 1);

            // console.log('Source Call:', String(inMsg.scall).yellow);
            // console.log('Dest Call:', String(inMsg.dcall).yellow);
            // console.log('Timestamp:', inMsg.timeStamp);
            // console.log('Outbound Seq No:', inMsg.outboundSeqNo);
            // console.log('Inbound Seq No:', inMsg.inboundSeqNo);
            // console.log('CMD:', (this.getCmdType(inMsg.cmdType) || "UNKNOWN").green);

            // Information elements
            let infoElements = [];
            this.parseInfoElements(msg.slice(12), infoElements);
            inMsg.infoElements = infoElements;
            inMsg.senderInfo = info;

            // Look to see if there's an existing entry for this call
            inMsg.call = await this.Call.retrieveCall(inMsg);

            // Check for valid IP. Log as console error for now
            // TODO: IPv6 Support
            let address = new Address4(inMsg.senderInfo.address);

            if (!address.isValid()) {
                Log.error(`Client sent invalid IP address: ${inMsg.senderInfo.address}`);
                Log.error(JSON.stringify(inMsg));
            }

            if (inMsg.retransmit) {
                // Count the number of retransmits for a call
                if (typeof inMsg.call.retransmit === "undefined" || inMsg.call.retransmit === null) {
                    inMsg.call.retransmit = 0;
                } else {
                    inMsg.call.retransmit++;
                    // Log.debug(`[IN] RT? ${info.address} ${inMsg.call.retransmit}`.bold.underline.magenta);
                }
                this.Call.saveCall(inMsg.call);

                // Ignore every other packet
                if (mod(inMsg.call.retransmit, 2) == 0) {
                    // return inMsg;
                }

                // Not sure why we're sending back an Ack on every retransmit.
                // this.sendLagOrAck(inMsg, true);
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
                    this.sendPong(inMsg);
                    break;
                case this.CMD.LAGRQ:
                    this.sendLagOrAck(inMsg);
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

            Log.packet(inMsg);
            return inMsg;
        } catch (e) {
            Log.error(`Malformed packet or error ${info.address}:${info.port}: ${e}`)
            throw new Error(e);
        }
    }

    /**
     * Process REGREQ Packet
     *
     * @param inMsg
     * @returns {Promise<void>|void}
     */
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
            // console.log("?!?!?!?!?!?!?! VERIFYREGREQUEST ?!?!?!?!?!?!?!");
            let vRRResult = this.verifyRegRequest(inMsg, node, challengeResponse);
            inMsg.call.challenge = null;
            return vRRResult;
        } else if (node && parseInt(node) < 2000) {
            // Just REGACK invalid node #s with a huge retry time
            return this.sendRegAck(inMsg, true);
        }

        return this.sendRegAuth(inMsg);
    }

    /**
     * Send REGAUTH packet
     *
     * @param inMsg
     * @returns {Promise<void>}
     */
    async sendRegAuth(inMsg) {
        // Workaround for some clients that flood with REGREQ
        if (inMsg.call.outboundSeqNo > 30) {
            return this.sendInval(inMsg);
        }
        
        let buffer = this.getSourceDestBuf(inMsg);
        let tBuffer = this.getTimeStampBuf(inMsg.call.timeStamp);
        let username = this.getNode(inMsg.infoElements);
        let randomChallenge;

        if (typeof inMsg.call.challenge === "undefined" || inMsg.call.challenge === null) {
            randomChallenge = Util.generateRandomNumber(100000000, 999999999);
            inMsg.call.challenge = randomChallenge;
        } else {
            randomChallenge = inMsg.call.challenge;
        }

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
        Server.send(outMsgBuf, inMsg.senderInfo, inMsg, this.CMD.REGAUTH);
        this.Call.saveCall(inMsg.call);
    }

    /**
     * Verify REGREQ packet against HTTP API
     * @param inMsg
     * @param node
     * @param challengeResponse
     * @returns {Promise<void>}
     */
    async verifyRegRequest(inMsg, node, challengeResponse) {
        // May refactor in the future
        if (inMsg.cmdType === this.CMD.REGREQ) {
            let result = await RegisterApi.register(node, inMsg.call.challenge, challengeResponse.toString(), inMsg.senderInfo.address, inMsg.senderInfo.port)
            
            if (result) {
                inMsg.realPort = result.data.port || inMsg.senderInfo.port || 4569;
                return this.sendRegAck(inMsg);
            } else if (result === false) {
                // Noisy node!
                Log.debug(`Node ${node} is noisy!`.red);
                return this.sendRegAck(inMsg, true);
            }
        
        } else if (inMsg.cmdType === this.CMD.REGREL) {
            if (await RegisterApi.unregister(node, inMsg.call.challenge, challengeResponse.toString(), inMsg.senderInfo.address, inMsg.senderInfo.port)) {
                return this.sendRegRelease(inMsg);
            }
        }

        return this.sendRegReject(inMsg);
    }

    /**
     * Send REGACK Packet after successful registration
     *
     * @param inMsg
     * @param isInvalidNode
     */
    sendRegAck(inMsg, isInvalidNode = false) {
        let buffer = this.getSourceDestBuf(inMsg);
        let tBuffer = this.getTimeStampBuf(inMsg.call.timeStamp);
        let username = this.getNode(inMsg.infoElements);

        // Parse IP for sending back PEERADDRESS
        let ipArr = inMsg.senderInfo.address.match(/(\d{1,3})/g);
        let clientRefreshTime = [0,process.env.CLIENT_REFRESH_TIME];

        // Set refresh time to 65535 for mis-configured nodes
        // and send back apparent IP of 255.255.255.255
        if (isInvalidNode) {
            clientRefreshTime = [0x4F, 0xFF];
            ipArr = [0xFF,0xFF,0xFF,0xFF];
        }

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
            ...clientRefreshTime,
            this.IE.PEERADDRESS,
            16, // Length
            ...[0x02, 0x00], // Family FIXME
            ...Util.splitIntToByteArray(String(inMsg.realPort)),
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
        Server.send(outMsgBuf, inMsg.senderInfo, inMsg, this.CMD.REGACK);

        if (!isInvalidNode) {
            let shouldLog = Math.floor(Math.random() * 100) + 1;
            if (shouldLog <= 10 || process.env.APP_DEBUG) {
                Log.info(`Registered ${username} at ${inMsg.senderInfo.address}:${inMsg.realPort}`.magenta);
            }
        }

        this.Call.saveCall(inMsg.call);
    }

    /**
     * Send REGREJ packet after failed registration
     *
     * @param inMsg
     */
    sendRegReject(inMsg) {
        if (typeof inMsg.call.rejections === "undefined") {
            inMsg.call.rejections = 0;
        }

        inMsg.call.rejections++;

        if (inMsg.call.rejections > 1) {
            return this.sendRegAck(inMsg, true);
        }

        this.Call.saveCall(inMsg.call);

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
        Server.send(outMsgBuf, inMsg.senderInfo, inMsg, this.CMD.REGREJ);
        let username = this.getNode(inMsg.infoElements);
        Log.info(`Auth rejected for node ${username} (${inMsg.call.rejections}) at ${inMsg.senderInfo.address}:${inMsg.senderInfo.port}`.magenta);

    }

    /**
     * Send ACK after client requests REGREL (registration release) packet
     *
     * @param inMsg
     */
    sendRegRelease(inMsg) {
        return this.sendLagOrAck(inMsg, true, false);
    }

    /**
     * This command only needs the CMD and nothing else to respond
     *
     * @param inMsg
     * @param inMsg.senderInfo
     */
    sendPing(inMsg) {
        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo++,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.PING,
        ]);

        let outMsgBuf = Buffer.concat([this.getResponseBuf(inMsg, true), Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo, inMsg, this.CMD.PING);
        // this.Call.deleteCall(inMsg);
    }
    
    /**
     * This command only needs the CMD and nothing else to respond
     *
     * @param inMsg
     * @param inMsg.senderInfo
     */
    sendPong(inMsg) {
        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo++,
            inMsg.call.inboundSeqNo,
            6, // IAX
            this.CMD.PONG,
        ]);

        let outMsgBuf = Buffer.concat([this.getResponseBuf(inMsg, true), Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo, inMsg, this.CMD.PONG);
        // this.Call.deleteCall(inMsg);
    }

    /**
     * This command differs slightly from PONG, in that it needs the timestamp from the client repeated back
     * @param inMsg
     * @param ack
     * @param resetCallSeq
     */
    sendLagOrAck(inMsg, ack = false, resetCallSeq = true) {
        // Not sure if this is the best approach. May refactor later.
        if (ack && resetCallSeq) {
            this.Call.resetCallSeq(inMsg);
        }

        let cmd = ack ? this.CMD.ACK : this.CMD.LAGRP;
        let outMsg = new Uint8Array([
            inMsg.outboundSeqNo,
            inMsg.inboundSeqNo,
            6, // IAX
            (cmd)
        ]);

        let outMsgBuf = Buffer.concat([this.getResponseBuf(inMsg, true), Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo, inMsg, cmd);
    }

    /**
     * Send INVAL packet
     *
     * @param inMsg
     */
    sendInval(inMsg) {
        let outMsg = new Uint8Array([
            inMsg.call.outboundSeqNo,
            inMsg.call.inboundSeqNo,
            6,
            this.CMD.INVAL
        ])

        let outMsgBuf = Buffer.concat([this.getResponseBuf(inMsg, true), Buffer.from(outMsg)]);
        Server.send(outMsgBuf, inMsg.senderInfo, inMsg, this.CMD.INVAL);
        // console.error(`INVAL Sent to ${inMsg.call.scall}`.bgRed.white);
        this.Call.deleteCall(inMsg);
    }

    /**
     * Receive ACK packet
     *
     * @param inMsg
     * @returns {boolean}
     */
    receiveAck(inMsg) {
        if (!inMsg.call.new) {
            this.Call.deleteCall(inMsg);
            return true;
        }
    }

    /**
     * Receive VNAK (Out of sequence) Packet
     *
     * @param inMsg
     */
    receiveVnak(inMsg) {
        this.Call.resetCallSeq(inMsg);
        this.sendInval(inMsg);
    }

    /**
     * Create packet header for response
     *
     * @param inMsg
     * @param sendTheirTimestamp
     * @returns {Buffer}
     */
    getResponseBuf(inMsg, sendTheirTimestamp = false) {
        return Buffer.concat([
            this.getSourceDestBuf(inMsg),
            this.getTimeStampBuf(sendTheirTimestamp ? inMsg.timeStamp : inMsg.call.timeStamp)
        ]);
    }

    /**
     * Set source / dest call for response packet
     *
     * @param inMsg
     * @returns {Buffer}
     */
    getSourceDestBuf(inMsg) {
        let sourceDestArr = new Uint16Array([
            Util.checkAndSetBit(inMsg.call.dcall),
            inMsg.call.scall,
        ]);

        return Buffer.from(sourceDestArr.buffer).swap16();
    }

    /**
     * Set timeStamp for response packet
     *
     * @param timeStamp
     * @returns {Buffer}
     */
    getTimeStampBuf(timeStamp) {
        let tArr = new Uint32Array([timeStamp]);
        return Buffer.from(tArr.buffer).swap32(); // Swap for Endian
    }

    /**
     * Parse IE (Info Elements) from packet
     *
     * @param buffer
     * @param infoElements
     * @returns {boolean}
     */
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

            buffer = buffer.slice(2 + length);
            this.parseInfoElements(buffer, infoElements);
        } catch (e) {
            console.error(e);
        }
    }

    /**
     * Get Node # / Username from parsed packet's infoElements (IE)
     *
     * @param infoElements
     * @returns {null}
     */
    getNode(infoElements) {
        let node = null;

        _.each(infoElements, (v) => {
            if (v.type !== this.IE.USERNAME) return;
            node = v.data;
        });

        return node;
    }

    /**
     * Get CMD / Packet Type
     *
     * @param type
     * @returns {null}
     */
    getCmdType(type) {
        let cmdType = null;

        _.each(this.CMD, (v, k) => {
            if (v !== type) return;
            cmdType = k;
        })

        return cmdType;
    }

    /**
     * Get IE (info element) type
     *
     * @param type
     * @returns {null}
     */
    getInfoType(type) {
        let infoType = null;

        _.each(this.IE, (v, k) => {
            if (v !== type) return;
            infoType = k;
        })

        return infoType;
    }
}

module.exports = Iax;

const Log = require('./Log')
