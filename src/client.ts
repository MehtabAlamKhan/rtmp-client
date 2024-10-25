/* RTMP handshake using diffie hellman key exchange client side
   Author - Mehtab Alam Khan 2024 */

import crypto from "node:crypto";
import net from "node:net";

const ENCRYPTED = 0x06;
const UNDOCUMENTED = 0x08;
const UNENCRYPTED = 0x03;
const RTMP_SIG_SIZE = 1536;

const socket = net.createConnection({ host: "127.0.0.1", port: 1935 }, () => {
  socket.write(Buffer.from([UNENCRYPTED]));
  let C1 = createC1Sig(UNENCRYPTED);
  // let dhpkl = getClientDhOffset;
  socket.write(C1);
});

socket.on("data", (data) => {});

socket.on("close", () => {
  console.log("SERVER DISCONNECTED");
});
socket.on("error", (err) => console.log(err));

function createC1Sig(commandType: number) {
  if (ENCRYPTED) {
    /*
  if encrypted
  0:3        : 32-bit system time, network byte ordered (htonl)
  4:7        : Client Version (e.g., 0x09 0x0 0x7c 0x2)
  8:11       : Obfuscated pointer to "Genuine FP" key 
  12:1531    : Random Data, 128-bit Diffie-Hellmann key, and "Genuine FP" key.
  1532:1535  : Obfuscated pointer to the 128-bit Diffie-Hellmann key 
  */
    const clientSig = Buffer.alloc(RTMP_SIG_SIZE);
    clientSig.writeUInt32BE(Math.floor(Date.now() / 1000));

    return clientSig;
  } else {
    //unencrypted. most cases
    let timeStamp = Buffer.from([Math.floor(Date.now() / 1000)]);
    let C0 = Buffer.alloc(1, UNENCRYPTED);
    return Buffer.concat([timeStamp, crypto.randomBytes(1532)]);
  }
}
