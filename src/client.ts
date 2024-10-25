/* RTMP handshake using diffie hellman key exchange client side
   Author - Mehtab Alam Khan 2024 */

import crypto from "node:crypto";
import net from "node:net";

/* 2048 is the prime number size (modulus size)
   it will automatically create predefined base(generator) and modulus for us */
const dh = crypto.createDiffieHellman(800);

/* this will generate both public and private
   keys but will return public key only */
const clientPublicKey = dh.generateKeys();

const clientPrivateKey = dh.getPrivateKey(); // we need to call the generateKeys first to get this
const clientVersion = Buffer.from([3, 0, 0, 0]);

const socket = net.createConnection({ host: "127.0.0.1", port: 1935 }, () => {
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
    const hmac = crypto.createHmac("sha256", sharedSecretKey);
    const expectedHmac = hmac.update(clientPublicKey).digest();

    if (!expectedHmac.equals(serverHmac)) {
      console.log("INVALID HMAC");
      socket.destroy();
      return;
    }

    const clientHmac = crypto.createHmac("sha256", sharedSecretKey).update(serverPublicKey).digest();
    socket.write(clientHmac);
  }
});

socket.on("close", () => {
  console.log("SERVER DISCONNECTED");
});
socket.on("error", (err) => console.log(err));
