/**
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @author Jason VE3YCA
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license AGPL-3.0-or-later
 */
const Log = {
    packet(inMsg) {
        return;
        let output = this.getDateLog();
        output += `[IN-${process.pid}] ${inMsg.senderInfo.address}:${inMsg.senderInfo.port} `;
        output += `[${Iax.getCmdType(inMsg.cmdType).green} ${inMsg.scall}->${inMsg.dcall}] `;
        output += `[${inMsg.outboundSeqNo}:${inMsg.inboundSeqNo}]`;
        console.log(output);
    },
    packetOut(cmd, inMsg) {
        return;
        let output = this.getDateLog();
        let zeroCall = inMsg.dcall === 0 ? `${inMsg.dcall}->` : '';
        output += `[OUT-${process.pid}] ${inMsg.senderInfo.address}:${inMsg.senderInfo.port} `;
        output += `[${Iax.getCmdType(cmd).green} `
        if (typeof inMsg.call !== 'undefined') {
            output += `${zeroCall}${inMsg.call.dcall}->${inMsg.scall}] `;
            output += `[${inMsg.call.outboundSeqNo}:${inMsg.call.inboundSeqNo}]`;
        }
        console.log(output)
    },
    info(...data) {
        console.info(this.getDateLog() + data);
    },
    debug(...data) {
        console.log(this.getDateLog() + data);
    },
    error(...data) {
        console.error((this.getDateLog() + data).red);
    },
    getDateLog() {
        return '';
        return `[${this.getDate()}] `;
    },
    getDate() {
        return moment().format('YYYY-MM-DD HH:mm:ss');
    }
}

module.exports = Log;

const moment = require('moment');
const Iax = new (require('./Iax'));
