const moment = require('moment');
const Util = require('./Util.js');
const crypto = require('crypto');
const _ = require('lodash');

const Call = {
    calls: new Map(),
    retrieveCall(inMsg) {
        let call = this.calls.get(this.getCallHash(inMsg));

        if (typeof call === "undefined") {
            return this.createCall(inMsg);
        } else {
            console.log(`\nFound call ${call.scall}`.green);
            call.inboundSeqNo++;
            call.timeStamp = moment().diff(call.created_at, 'millisecond');
        }

        call.new = false;
        return call;
    },
    createCall(inMsg) {
        let call = _.pick(inMsg, [
            'scall',
            'dcall',
            'senderInfo',
        ])

        call.inboundSeqNo = 0;
        call.outboundSeqNo = 0;
        call.ttl = process.env.CALL_TTL; // How many seconds before a call is considered abandoned
        call.timeStamp = 0;
        call.created_at = moment();
        call.new = true;
        
        if (inMsg.dcall === 0 || inMsg.dcall === 32768) {
            call.dcall = Util.addBitwise(32768, Util.generateRandomNumber(3,32767));
        }

        let hash = this.getCallHash(inMsg);
        console.log(`\nCreating call ${inMsg.scall}`.green);
        this.calls.set(hash, call);

        return call;
    },
    deleteCall(inMsg) {
        this.calls.delete(this.getCallHash(inMsg));
        console.log(String('Deleted call ' + inMsg.call.scall).red);
    },
    getCallHash(inMsg) {
        return crypto.createHash('md5').update(
            String(inMsg.scall) +
            inMsg.senderInfo.ip +
            String(inMsg.senderInfo.port)
        ).digest("hex");
    },
    resetCallSeq(inMsg) {
        inMsg.call.outboundSeqNo = inMsg.inboundSeqNo;
        inMsg.call.inboundSeqNo  = inMsg.outboundSeqNo;
    },
    pruneCalls() {
        let now = moment();

        for (let [k, v] of this.calls) {
            if (v.created_at.diff(now, 'seconds') >= v.ttl) {
                console.log(`Pruning old call ${v.scall}`.yellow)
                this.calls.delete(k);
            }
        }
    }
}

module.exports = Call;