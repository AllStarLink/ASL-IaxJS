const udp = require('dgram');
const Server = {
    init: (messageCallback) => {
        this.server = udp.createSocket('udp4');
        this.server.bind(4569);

        this.server.on('message', messageCallback);
        
        // emits when socket is ready and listening for datagram msgs
        this.server.on('listening', () => {
            let address = this.server.address();
            let port = address.port;
            let family = address.family;
            let ipaddr = address.address;
            console.log(`Server listening at ${ipaddr}:${port} (${family})`);
        });

        // emits when any error occurs
        this.server.on('error', (error) => {
            console.log('Error: ' + error);
            this.server.close();
        });

        return this.server;
    },
    send: (buffer, senderInfo, inMsg = null, cmd = null) => {
        this.server.send(buffer, senderInfo.port, senderInfo.address, function (error) {
            if (inMsg && cmd) {
                Log.packetOut(cmd, inMsg);
            }
            // console.log('!!!!!!!!!!!!!!!!! Data sent !!!!!!!!!!!!!!!!!!');
        });
    }
}

module.exports = Server;

const Log = require('./Log');