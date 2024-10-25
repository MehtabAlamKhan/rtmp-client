"use strict";
/* RTMP handshake using diffie hellman key exchange client side
   Author - Mehtab Alam Khan 2024 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_net_1 = __importDefault(require("node:net"));
/* 2048 is the prime number size (modulus size)
   it will automatically create predefined base(generator) and modulus for us */
const dh = node_crypto_1.default.createDiffieHellman(800);
/* this will generate both public and private
   keys but will return public key only */
const clientPublicKey = dh.generateKeys();
const clientPrivateKey = dh.getPrivateKey(); // we need to call the generateKeys first to get this
const clientVersion = Buffer.from([3, 0, 0, 0]);
const socket = node_net_1.default.createConnection({ host: "127.0.0.1", port: 1935 }, () => {
    socket.write(clientVersion);
    socket.write(clientPublicKey.toString("base64"));
});
let sharedSecretKey = "";
socket.on("data", (data) => {
    if (!sharedSecretKey.length) {
        const serverPublicKey = Buffer.from(data.toString("base64"), "base64");
        //compute shared secret key (this is the final key)
        const sharedSecretKey = dh.computeSecret(serverPublicKey);
        const serverHmac = data.subarray(-32);
        const hmac = node_crypto_1.default.createHmac("sha256", sharedSecretKey);
        const expectedHmac = hmac.update(clientPublicKey).digest();
        if (!expectedHmac.equals(serverHmac)) {
            console.log("INVALID HMAC");
            socket.destroy();
            return;
        }
        const clientHmac = node_crypto_1.default.createHmac("sha256", sharedSecretKey).update(serverPublicKey).digest();
        socket.write(clientHmac);
    }
});
socket.on("close", () => {
    console.log("SERVER DISCONNECTED");
});
socket.on("error", (err) => console.log(err));
//# sourceMappingURL=client.js.map