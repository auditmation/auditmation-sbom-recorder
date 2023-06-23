const exec = require('@actions/exec');
const { expect } = require('chai');
const path = require('path');

describe('Auditmation SBOM Recorder Test', function () {
  it('Should upload an sbom from an artifact', async () => {
    const env = {
      'INPUT_API-KEY': process.env.API_KEY,
      'INPUT_ORG-ID': process.env.ORG_ID,
      'INPUT_BOUNDARY-ID': '371d39bb-4afc-4640-8aac-4225305046d6',
      INPUT_URL: process.env.URL,
      'INPUT_PACKAGE': '@auditmation/hub-client@latest',
      'INPUT_FILE-PATH': 'bom.json',
      ...process.env,
    };

    const out = await exec.exec('node', [path.join(__dirname, '..', 'src', 'index.js')], { env });
    console.log('OUT', out);
    expect(out).to.equal(0);
  }).timeout(30000);
});
