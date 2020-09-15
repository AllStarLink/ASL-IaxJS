#!/usr/bin/env node
/**
 * IAX2 Server for Registrations
 *
 * @author Rob Vella KK9ROB <me@robvella.com>
 * @copyright AllStarLink, Inc
 * @license GPL-3.0-only
 */

require('dotenv').config({ path: __dirname + '/.env' });

const cluster = require('cluster');
const colors = require('colors');
const numCPUs = require('os').cpus().length;

if (cluster.isMaster) {
    // Fork workers.
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        console.log(`worker ${worker.process.pid} died`);
    });
} else {
    const asyncRedis = require("async-redis");
    const redis = asyncRedis.createClient({
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT,
        // password: process.env.REDIS_PASSWORD || undefined
    });
   
    const Server = require('./lib/Server.js');
    const Iax = new (require('./lib/Iax'));
    
    redis.on('ready', async () => {
        Iax.Call.setRedis(redis);

        Server.init((msg, info) => {
            try {
                Iax.receiveMessage(msg, info);
            } catch (e) {
                console.error(e);
            }
        });
    })
}

