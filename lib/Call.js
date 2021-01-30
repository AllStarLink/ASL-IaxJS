/**
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license AGPL-3.0-or-later
 */
const moment = require('moment');
const Util = require('./Util');
const crypto = require('crypto');
const _ = require('lodash');

class Call {
    constructor() {
        this.calls = new Map();
        this.redis = null;
    }
    /**
     * @param redis-async redis 
     * @returns {Call}
     */
    setRedis(redis) {
        this.redis = redis;
        return this;
    }
    /**
     * 
     * @param inMsg
     * @returns {Promise<any>}
     */
    async retrieveCall(inMsg) {
        let hash = this.getCallHash(inMsg);
        let call;
        
        if (this.redis) {
            call = await this.redis.get(hash);
            if (call) call = JSON.parse(call);
        } else {
            call = this.calls.get(hash);
        }
        
        if (typeof call === "undefined" || !call) {
            return this.createCall(inMsg);
        }
        
        // console.log(`\nFound call ${call.scall}`.green);
        call.inboundSeqNo++;
        call.timeStamp = moment().diff(call.created_at, 'millisecond');
        call.new = false;
        this.saveCall(call);
        
        return call;
    }
    createCall(inMsg, client = false) {
        let call = _.pick(inMsg, [
            'scall',
            'dcall',
            'senderInfo',
        ])

        call.inboundSeqNo = 0;
        call.outboundSeqNo = 0;
        call.ttl = parseInt(process.env.CALL_TTL); // How many seconds before a call is considered abandoned
        call.timeStamp = 0;
        call.created_at = moment();
        call.new = true;
        
        if (!client && inMsg.dcall === 0 || inMsg.dcall === 32768) {
            call.dcall = Util.addBitwise(32768, Util.generateRandomNumber(3,32767));
        }

        call.hash = this.getCallHash(inMsg);
        // console.log(`\nCreating call ${inMsg.scall} ${inMsg.dcall}`.green);
        this.saveCall(call);
        return call;
    }
    saveCall(call) {
        if (this.redis) {
            // Expire after TTL
            this.redis.set(call.hash, JSON.stringify(call), 'EX', call.ttl);
        } else {
            this.calls.set(call.hash, call);
        }
    }
    async deleteCall(inMsg) {
        if (this.redis) {
            await this.redis.del(this.getCallHash(inMsg));
        } else {
            this.calls.delete(this.getCallHash(inMsg));
        }
        
        // console.log(String('Deleted call ' + inMsg.call.scall).red);
    }
    getCallHash(inMsg) {
        return crypto.createHash('md5').update(
            String(inMsg.scall) +
            inMsg.senderInfo.ip
            // String(inMsg.senderInfo.port)
        ).digest("hex");
    }
    resetCallSeq(inMsg) {
        inMsg.call.outboundSeqNo = inMsg.inboundSeqNo;
        inMsg.call.inboundSeqNo  = inMsg.outboundSeqNo;
        this.saveCall(inMsg.call);
    }
    /**
     * Only used on iaxClient 
     */
    pruneCalls() {
        let now = moment();

        for (let [k, v] of this.calls) {
            if (v.created_at.diff(now, 'seconds') >= v.ttl) {
                Log.debug(`Pruning old call ${v.scall}`.yellow)
                this.calls.delete(k);
            }
        }
    }
}

module.exports = Call;

const Log = require('./Log');
