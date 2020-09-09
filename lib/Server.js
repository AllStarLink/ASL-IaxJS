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
            console.log('Server is listening at port ' + port);
            console.log('Server ip: ' + ipaddr);
            console.log('Server is IP4/IP6 : ' + family);
        });

        // emits when any error occurs
        this.server.on('error', (error) => {
            console.log('Error: ' + error);
            this.server.close();
        });

        return this.server;
    },
    send: (buffer, address, port) => {
        this.server.send(buffer, port, address, function (error) {
            console.log('!!!!!!!!!!!!!!!!! Data sent !!!!!!!!!!!!!!!!!!');
        });
    }
}

module.exports = Server;