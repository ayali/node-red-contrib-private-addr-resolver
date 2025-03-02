module.exports = function(RED) {
    const crypto = require('crypto');

    function PrivateAddrResolverNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function(msg, send, done) {
            const macAddress = config.mac_address || msg.payload.mac_address;
            const irkInput = config.irk || msg.payload.irk;

            let irkHex;
            if (irkInput.trim().endsWith("=")) {
                const temp = Buffer.from(irkInput, 'base64');
                const reversedBuffer = Buffer.alloc(temp.length);
                for (let i = 0; i < temp.length; i++) {
                    reversedBuffer[i] = temp[temp.length - 1 - i];
                }
                irkHex = reversedBuffer.toString('hex');
                if (reversedBuffer.length !== 16) {
                    node.error("IRK must be 16 bytes (128 bits)", msg);
                    done();
                    return;
                }
            } else {
                irkHex = irkInput;
            }

            if (!macAddress || !irkHex) {
                node.error("mac_address or IRK missing", msg);
                done();
                return;
            }

            try {
                const macClean = macAddress.replace(/:/g, "");
                if (macClean.length !== 12) {
                    node.error("mac_address must represent 6 bytes", msg);
                    done();
                    return;
                }
                const macBuffer = Buffer.from(macClean, 'hex');

                // Check RPA flag (first two bits must be 01)
                if ((macBuffer[0] & 0xC0) !== 0x40) {
                    // node.warn("Not an RPA (first two bits not 01)");
                    const msgOut = [null, msg]; // Non-match
                    send(msgOut);
                    done();
                    return;
                }

                const receivedHash = macBuffer.slice(0, 3);
                const prand = macBuffer.slice(3);

                const computedPrand = computeBLEHash(irkHex, receivedHash);

                const isHashMatch = computedPrand.equals(prand);

                const msgOut = [null, null];
                if (isHashMatch) {
                    msgOut[0] = msg;
                } else {
                    msgOut[1] = msg;
                }

                send(msgOut);
                done();
            } catch (err) {
                node.error("Error processing mac_address: " + err.message, msg);
                done(err);
            }
        });
    }

    function computeBLEHash(irkHex, receivedHashBuffer) {
        const key = Buffer.from(irkHex, 'hex');
        const inputBlock = Buffer.alloc(16, 0);
        receivedHashBuffer.copy(inputBlock, 13);
        const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
        cipher.setAutoPadding(false);
        let encrypted = cipher.update(inputBlock);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return encrypted.slice(13, 16);
    }

    RED.nodes.registerType("private-addr-resolver", PrivateAddrResolverNode);
};
