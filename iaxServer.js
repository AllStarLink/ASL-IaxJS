#!/usr/bin/env node
/**
 * IAX2 Server for Registrations
 *
 * @author Rob Vella, KK9ROB <me@robvella.com>
 * @copyright Copyright (c) 2020 AllStarLink, Inc
 * @license AGPL-3.0-or-later
 */
require('dotenv').config({ path: __dirname + '/.env' });

const cluster = require('cluster');
const colors = require('colors');
const numCPUs = require('os').cpus().length * process.env.CPU_MULTIPLIER;

if (cluster.isMaster) {
    console.log('Starting ' + numCPUs + ' forks');

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
        }, process.env.LISTEN_PORT);
    })
}

