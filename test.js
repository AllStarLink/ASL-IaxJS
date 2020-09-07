let a = (4569)
    .toString(16)
    .match(/.{1,2}/g)
    .map(b => parseInt(b.padStart(4, '0x')))
// a = "10.0.0.1".match(/(\d{1,3})/g)
console.log(a)
// let b = Buffer.from(new Uint8Array([45,69]).buffer);
// console.log(b)

let x = new Uint16Array([4569]);

console.log(bufferToHex(x.buffer));
function bufferToHex (buffer) {
    return [...new Uint8Array (buffer)]
        .map (b => b.toString (16).padStart (2, "0"))
        .join ("");
}
