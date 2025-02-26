import { WitnessTester } from "circomkit";
import { circomkit, hexToBytes, toUint32Array, uintArray32ToBits } from "./common";

describe("mimc", () => {
    it("should work", async () => {
        let circuit: WitnessTester<["ins"], ["outs"]>;
        circuit = await circomkit.WitnessTester(`ChaCha20`, {
            file: "mimc/mimc",
            template: "MiMC",
            params: [3, 1]
        });
        await circuit.expectPass({
            ins: [0n, 1n, 567778336660098848776366662228888333n],
        }, { outs: [12525131868496031425744154881744336661020056362076131525086600857748260152186n] });
    });
});