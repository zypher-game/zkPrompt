import { assert } from "chai";
import { WitnessTester } from "circomkit";
import { circomkit, hexBytesToBigInt, hexToBytes } from "./common";

describe("aes-ctr", () => {
  it("should work", async () => {
    let circuit_one_block: WitnessTester<["key", "iv", "plainText"], ["cipherText"]>;
    circuit_one_block = await circomkit.WitnessTester(`aes-ctr`, {
      file: "aes-ctr/aes-ctr",
      template: "AESCTR",
      params: [96],
    });

    const key = hexToBytes('9bc2a070ad6a05ca5c9b72b2693bbfb7');
    const iv = hexToBytes('05050354fb7523f9ba9693b0');
    const pt = hexToBytes('546563686e6f6c6f677920636f6e6e656374732070656f706c652c6f6666657273206f70706f7274756e69746965732c616e642070726573656e7473206368616c6c656e6765732c206d616b696e67206c696665206d6f726520656173696572');
    const ct = hexToBytes('54950e0def223f4698e5b92a1869164f949d34b3dab21cb90fe14afdbd271bdd2f6dc118fac34af917722d17ca1aa9aa6ca07090988c9ba6c89bb850e97b3dbbf4a839a5f068cbd582c6da3ebb982f9350ea47a4bd4fa933711378b47aa94d1c');
   
    const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: pt }, ["cipherText"])
    assert.deepEqual(witness.cipherText, hexBytesToBigInt(ct))
  });
});








