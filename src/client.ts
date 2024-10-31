/* RTMP handshake using diffie hellman key exchange client side
   Author - Mehtab Alam Khan 2024 */

import crypto from "node:crypto";
import net from "node:net";

const ENCRYPTED = 0x06;
const UNDOCUMENTED = 0x08;
const UNENCRYPTED = 0x03;

const RTMP_SIG_SIZE = 1536;
const SHA256DL = 32; // SHA 256-byte Digest Length
const GenuineFMSConst = Buffer.from("Genuine Adobe Flash Media Server 001"); // 36 bytes
const GenuineFPConst = Buffer.from("Genuine Adobe Flash Player 001"); // 30 bytes
const RandomCrud = Buffer.from([
  0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8, 0x2e, 0x00, 0xd0, 0xd1, 0x02, 0x9e, 0x7e, 0x57, 0x6e, 0xec, 0x5d,
  0x2d, 0x29, 0x80, 0x6f, 0xab, 0x93, 0xb8, 0xe6, 0x36, 0xcf, 0xeb, 0x31, 0xae,
]);

const socket = net.createConnection({ host: "127.0.0.1", port: 1935 }, () => {
  let C0C1 = createC1Sig(ENCRYPTED);
  socket.write(C0C1);
});

socket.on("data", (data) => {});

socket.on("close", () => {
  console.log("SERVER DISCONNECTED");
});
socket.on("error", (err) => console.log(err));

function createC1Sig(commandType: number) {
  if (commandType == ENCRYPTED) {
    const clientSig = Buffer.alloc(RTMP_SIG_SIZE + 1, crypto.randomBytes(RTMP_SIG_SIZE + 1));
    //C0 command byte. 1 byte
    clientSig.writeUInt8(ENCRYPTED);

    // C1 if encrypted
    // 0:3        : 32-bit system time, network byte ordered (htonl)
    // 4:7        : Client Version (e.g., 0x09 0x0 0x7c 0x2)
    // 8:11       : Obfuscated pointer to "Genuine FP" key
    // 12:1531    : Random Data, 128-bit Diffie-Hellmann key, and "Genuine FP" key 30.
    // 1532:1535  : Obfuscated pointer to the 128-bit Diffie-Hellmann key
    //time
    clientSig.writeUInt32BE(Math.floor(Date.now() / 1000), 1);
    // client version
    clientSig.writeUIntBE(0x090007c2, 5, 4);
    let cDho = getClientDHOffset(clientSig.subarray(1533));
    const DHPrivateKeyC = crypto.randomBytes(16);
    const DHPublicKeyC = crypto.randomBytes(16);
    DHPublicKeyC.copy(clientSig, cDho + 1, 0);
    GenuineFPConst.copy(clientSig, cDho + 1 + 16, 0);
    return clientSig;
  } else {
    //unencrypted. most cases
    let timeStamp = Buffer.alloc(4);
    timeStamp.writeUInt32BE(Math.floor(Date.now() / 1000));
    let C0 = Buffer.alloc(1, UNENCRYPTED);
    return Buffer.concat([C0, timeStamp, crypto.randomBytes(1532)]);
  }
}

// Calculate the offset of the client's Diffie-Hellmann key
function getClientDHOffset(bytes: Buffer): number {
  const offset = bytes.readUInt32BE(0);
  return (offset % 632) + 772; // Calculate offset as per the spec
}
