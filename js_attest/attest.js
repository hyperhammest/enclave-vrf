const { AttestationClient } = require("@azure/attestation");

async function attest(attestUrl, reportHex, rtDataHex) {
  const client = new AttestationClient(attestUrl);
  const reportData = Buffer.from(reportHex, 'hex');
  const runtimeData = Buffer.from(rtDataHex, 'hex');

  return await client.attestOpenEnclave(reportData, {
    runTimeData: runtimeData
  });
}

module.exports.attest = attest;
