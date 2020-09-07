const Iax = {
    callTokenReq(inMsg, senderInfo) {
        console.log('############## NEED CALL TOKEN!!!!#############');

        let sourceDestArr = new Uint16Array([
            0x8001,
            inMsg.scall
        ]);

        let tsArr = new Uint32Array([1]);
        let buffer = Buffer.from(sourceDestArr.buffer).swap16();
        let tsBuffer = Buffer.from(tsArr.buffer).swap32();
        buffer = Buffer.concat([buffer, tsBuffer]);

        let time = Math.floor(Date.now() / 1000);
        let token = time + "?" + randomstring.generate(40);

        let outMsg = new Uint8Array([
            0,
            1,
            6,
            Iax.CMD.CALLTOKEN,
            Iax.IE.CALLTOKEN,
            token.length
        ]);

        let tokenBuf = Buffer.from(token);
        let outMsgBuf = Buffer.concat([buffer, Buffer.from(outMsg), tokenBuf]);
        console.log(outMsgBuf);
        console.log(tokenBuf);
        Server.send(outMsgBuf, senderInfo.address, senderInfo.port);
    },
}