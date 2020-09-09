const Log = require('./lib/Log');
const colors = require('colors');

let inMsg = {
    scall: 999,
    dcall: 10101,
    cmdType: 13,
    inboundSeqNo: 0,
    outboundSeqNo: 1,
    call: {
        inboundSeqNo: 1,
        outboundSeqNo: 0
    },
    senderInfo: {
        address: '10.1.1.1',
        port: 4569
    }
}

Log.packet(inMsg)