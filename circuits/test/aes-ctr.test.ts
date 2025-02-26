import { assert } from "chai";
import { WitnessTester } from "circomkit";
import { circomkit, hexBytesToBigInt, hexToBytes } from "./common";

describe("aes-ctr", () => {
  it("should work", async () => {
    let circuit_one_block: WitnessTester<["key", "iv", "plainText"], ["cipherText"]>;
    circuit_one_block = await circomkit.WitnessTester(`aes-ctr`, {
      file: "aes-ctr/aes-ctr",
      template: "AESCTR",
      params: [90],
    });

    const key = hexToBytes('9bc2a070ad6a05ca5c9b72b2693bbfb7');
    const iv = hexToBytes('05050354fb7523f9ba9693b0');
    const pt = hexToBytes('474554202f20485454502f312e310d0a486f73743a207777772e727573742d6c616e672e6f72670d0a436f6e6e656374696f6e3a20636c6f73650d0a4163636570742d456e636f64696e673a206964656e746974790d0a0d0a17');
    const ct = hexToBytes('47b53945ae6d1b7dabccb67859367520bf8634e790f704be14aa14e7a83553c33d23c946e5de5f80685f2b0dcd1ab9f264a17a8ac89d92bade90c129887b36bfe8b0718ef96ed79dcbc5dc6ff29f2cd652f748b5e42fcc4c1e24');
   
    const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: pt }, ["cipherText"])
    assert.deepEqual(witness.cipherText, hexBytesToBigInt(ct))
  });
});








