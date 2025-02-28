module.exports = function(RED) {
    const aesCmac = require('node-aes-cmac').aesCmac;

    function PrivateAddrResolverNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function(msg, send, done) {
            // Get mac-address and IRK from msg.payload or config
            const macAddress = msg.payload['mac-address'] || msg['mac-address'] || config['mac-address'];
            const irk = msg.payload.irk || msg.irk || config.irk;

            // Validate inputs
            if (!macAddress || !irk) {
                node.error("mac-address or IRK missing", msg);
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

                // BUGBUG: Log the computed hash for debugging
                node.warn("Computed Hash: " + computedHash.toString('hex').toUpperCase());

                // Prepare output messages (null for unused outputs)
                const msgOut = [null, null];
                if (isHashMatch) {
                    msgOut[0] = { payload: macAddress }; // Output 1: There is a match
                } else {
                    msgOut[1] = { payload: macAddress }; // Output 2: No match
                }

                // Send to the appropriate output
                send(msgOut);
                done();
            } catch (err) {
                node.error("Error processing mac-address: " + err.message, msg);
                done(err);
            }
        });
    }

    RED.nodes.registerType("private-addr-resolver", PrivateAddrResolverNode);
};
