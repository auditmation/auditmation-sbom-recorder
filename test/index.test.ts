import * as exec from '@actions/exec';
import { expect } from 'chai';
import * as path from 'path';
import { fileURLToPath } from 'url';

// ESM equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('Auditmation SBOM Recorder Test', function () {
  it('Should upload an sbom from an artifact', async function () {
    // Check if required environment variables are present
    if (!process.env.API_KEY || !process.env.ORG_ID || !process.env.URL) {
      console.log('Skipping test: Missing required environment variables (API_KEY, ORG_ID, URL)');
      this.skip();
      return;
    }

    const env: NodeJS.ProcessEnv = {
      'INPUT_API-KEY': process.env.API_KEY,
      'INPUT_ORG-ID': process.env.ORG_ID,
      'INPUT_BOUNDARY-ID': '4bfa191b-b40f-4c3e-8a3b-a15bb4f6448d',
      INPUT_URL: process.env.URL,
      'INPUT_PACKAGE': '@auditmation/file-service-app@latest',
      'INPUT_FILE-PATH': 'bom.json',
      'INPUT_PRODUCT-ID': '23cf2909-5c5e-5546-be5f-7f167d1f1c16',
      ...process.env,
    };

    // Note: We're executing the compiled dist/index.js, not the TS source
    const indexPath = path.join(__dirname, '..', 'dist', 'index.js');
    const exitCode = await exec.exec('node', [indexPath], { env });

    console.log('Exit code:', exitCode);
    expect(exitCode).to.equal(0);
  });
});