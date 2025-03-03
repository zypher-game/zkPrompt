import { WitnessTester } from "circomkit";
import { circomkit, hexToBytes, toUint32Array, uintArray32ToBits } from "./common";
import { log } from "console";

describe("chacha20", () => {
    it("should work", async () => {
        let circuit: WitnessTester<["key", "nonce", "counter", "in"], ["out"]>;
        circuit = await circomkit.WitnessTester(`ChaCha20`, {
            file: "chacha20/chacha20",
            template: "ChaCha20",
            params: [16]
        });

        let key = Buffer.from(hexToBytes("2d1dd3fe94156f0063372d1523a10b542348f3ad7491fec44390ad24a2f3edc7"));
        let nonce = Buffer.from(hexToBytes("4a1f503da88baa6e582a2fe1"));
        let pt = Buffer.from(hexToBytes("546f6d6f72726f772077696c6c20626520626574746572212121212121212121546f6d6f72726f772077696c6c20626520626574746572212121212121212121"));
        let ct = Buffer.from(hexToBytes("8160bef4ce75a63610b85375619fe20c3bcc2e154389b74741755681dd0ad37b2201671a36852729da74b958182bafb4d9bd6c2b348ae3277aaa056e1230ef9d"));

        const ciphertextBits = uintArray32ToBits(toUint32Array(ct))
        const plaintextBits = uintArray32ToBits(toUint32Array(pt))
        const counterBits = uintArray32ToBits([1])[0]
        await circuit.expectPass({
            key: uintArray32ToBits(toUint32Array(key)),
            nonce: uintArray32ToBits(toUint32Array(nonce)),
            counter: counterBits,
            in: plaintextBits,
        }, { out: ciphertextBits });

        const w2 = await circuit.expectPass({
            key: uintArray32ToBits(toUint32Array(key)),
            nonce: uintArray32ToBits(toUint32Array(nonce)),
            counter: counterBits,
            in: ciphertextBits,
        }, { out: plaintextBits });
    });
});