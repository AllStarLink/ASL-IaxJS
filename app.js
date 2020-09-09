require('dotenv').config();

const Server = require('./lib/Server.js');
const Call = require('./lib/Call.js');
const Iax = require('./lib/Iax');
const Log = require('./lib/Log');
const colors = require('colors');

Server.init((msg, info) => {
    try {
        Iax.receiveMessage(msg, info);
    } catch (e) {
        console.error(e);
    }
});

setInterval(() => {
    Call.pruneCalls();
}, 5000)
