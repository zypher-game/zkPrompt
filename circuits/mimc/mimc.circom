pragma circom 2.1.6;

include "circomlib/circuits/mimcsponge.circom";


template MiMC(nInputs, nOutputs) {
  signal input ins[nInputs];
  signal output outs[nOutputs];

   component mimc = MiMCSponge(nInputs, 220, nOutputs);
   mimc.ins <== ins;
   mimc.k <== 0; 
   outs <== mimc.outs;
 }