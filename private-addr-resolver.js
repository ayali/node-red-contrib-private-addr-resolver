module.exports = function(RED) {
    const aesCmac = require('node-aes-cmac').aesCmac;

    function PrivateAddrResolverNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function(msg, send, done) {
            // Get mac_address and IRK, prioritizing node config over msg.payload
            const macAddress = config.mac_address || msg.payload.mac_address;
            const irk = config.irk || msg.payload.irk;

            // Validate inputs
            if (!macAddress || !irk) {
                node.error("mac_address or IRK missing", msg);
                done();
                return;
            }

            try {
                // Normalize mac-address (remove colons) and convert to Buffer
                const macClean = macAddress.replace(/:/g, "");
                const macBuffer = Buffer.from(macClean, 'hex');

                // Extract prand (last 3 bytes) and received hash (first 3 bytes)
                const prand = macBuffer.slice(3);
                const receivedHash = macBuffer.slice(0, 3);

                // Compute AES-CMAC hash with IRK and prand
                const computedHash = aesCmac(Buffer.from(irk, 'hex'), prand, { returnAsBuffer: true }).slice(0, 3);

                // Check if hashes match
                const isHashMatch = computedHash.equals(receivedHash);

                // Prepare output messages (null for unused outputs)
                const msgOut = [null, null];
                if (isHashMatch) {
                    msgOut[0] = msg; // Output 1: There is a match
                } else {
                    msgOut[1] = msg; // Output 2: No match
                }

                // Send to the appropriate output
                send(msgOut);
                done();
            } catch (err) {
                node.error("Error processing mac_address: " + err.message, msg);
                done(err);
            }
        });
    }

    RED.nodes.registerType("private-addr-resolver", PrivateAddrResolverNode);
};
