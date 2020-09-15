/**
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license GPL-3.0-only
 */
const udp = require('dgram');
const Server = {
    /**
     * 
     * @param messageCallback
     * @param port
     * @param listeningCallback
     * @returns {Socket}
     */
    server: null,
    init: (messageCallback, port = 4569, listeningCallback = null) => {
        this.server = udp.createSocket('udp4');
        this.server.bind(port);

        this.server.on('message', messageCallback);
        
        // emits when socket is ready and listening for datagram msgs
        this.server.on('listening', () => {
            let address = this.server.address();
            let port = address.port;
            let family = address.family;
            let ipaddr = address.address;
            Log.info(`Server listening at ${ipaddr}:${port} (${family})`);

            if (listeningCallback) {
                listeningCallback(this.server);
            }
        });

        // emits when any error occurs
        this.server.on('error', (error) => {
            Log.error(`Socket Error: ${error}`.red);
            this.server.close();
        });

        return this.server;
    },
    /**
     * 
     * @param buffer
     * @param senderInfo
     * @param inMsg
     * @param cmd
     */
    send: (buffer, senderInfo, inMsg = null, cmd = null) => {
        return new Promise((resolve, reject) => {
            this.server.send(buffer, senderInfo.port, senderInfo.address, (error) => {
                if (inMsg && cmd) {
                    // Log.packetOut(cmd, inMsg);
                }
              
                if (error) reject();
                else resolve();
            });
        });
    }
}

module.exports = Server;

const Log = require('./Log');