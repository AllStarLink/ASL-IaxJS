const Iax = require('./Iax');
const Server = require('./Server');
const Util = require('./Util');
const crypto = require('crypto');
const _ = require('lodash');

class IaxClient extends Iax {
    constructor(remote) {
        super();
        this.server = null;
        this.remote = remote;
        this.pruneCalls();
    }
    async receiveMessage(msg, info) {
        let inMsg = await super.receiveMessage(msg, info);

        switch (inMsg.cmdType) {
            case this.CMD.REGAUTH:
                this.receiveRegAuth(inMsg);
                break;
            case this.CMD.REGACK:
                this.receiveRegAck(inMsg);
                break;
            case this.CMD.REGREJ:
                this.receiveRegReject(inMsg);
                break;
            case this.CMD.INVAL:
                this.receiveInval(inMsg);
                break;
            default:
                break;
        }
        
        return inMsg;
    }
    setCredentials(username, secret) {
        this.username = username;
        this.secret = secret;
    }
    sendRegReq(inMsg = null) {
        let append = [];
        
        if (!inMsg) {
            // Dummy message to get us started
            inMsg = {
                dcall: Util.generateRandomNumber(3, 32767),
                scall: 0,
                timeStamp: 0,
                senderInfo: this.remote
            }

            inMsg.call = this.Call.createCall(inMsg);
            
            append = [
                this.IE.REFRESH,
                2,
                0,
                60
            ];
        } else {
            let challenge;
            
            // Find MD5 Challenge in inMsg
            _.each(inMsg.infoElements, (v) => {
                if (v.type !== this.IE.MD5CHALLENGE) return;
                challenge = v.data;
            });
            
            let md5 = crypto
                .createHash('md5')
                .update(String(challenge)+this.secret).digest("hex");

            append = [
                this.IE.MD5CHALLENGERESP,
                md5.length,
                ...Buffer.from(md5)
            ];
        }
        
        let buffer = this.getResponseBuf(inMsg);
        let outMsg = new Uint8Array([
            0,
            0,
            6, // IAX
            this.CMD.REGREQ,
            // IE Begin
            this.IE.USERNAME,
            this.username.length,
            ...Buffer.from(String(this.username)),
            ...append
        ]);

        let outMsgBuf = Buffer.concat([buffer, outMsg]);
        Server.send(outMsgBuf, this.remote, inMsg, this.CMD.REGREQ);
    }
    sendVnak(inMsg) {
        
    }
    sendAck(inMsg) {
        this.sendLagOrAck(inMsg, true, false);
    }
    receiveRegAuth(inMsg) {
        this.sendRegReq(inMsg);
    }
    receiveRegAck(inMsg) {
        this.sendAck(inMsg);
    }
    receiveRegReject(inMsg) {
        // Do nothing
    }
    receiveInval(inMsg) {
        this.Call.deleteCall(inMsg);
    }
    pruneCalls() {
        setInterval(() => {
            this.Call.pruneCalls();
        }, process.env.CALL_TTL * 1000)
    }
}

module.exports = IaxClient;

const Log = require('./Log');