import * as exec from '@actions/exec';
import { expect } from 'chai';
import * as path from 'path';
import { fileURLToPath } from 'url';

// ESM equivalent of __dirname
const filename = fileURLToPath(import.meta.url);
const dirname = path.dirname(filename);

describe('Auditmation SBOM Recorder Test', function () {
  it('Should upload an sbom from an artifact', async function () {
    // Check if required environment variables are present
    const requiredVars = ['API_KEY', 'ORG_ID', 'URL', 'BOUNDARY_ID', 'PRODUCT_ID'];
    const missingVars = requiredVars.filter((v) => !process.env[v]);
    if (missingVars.length > 0) {
      console.log(`Skipping test: Missing required environment variables (${missingVars.join(', ')})`);
      this.skip();
      return;
    }

    const env: NodeJS.ProcessEnv = {
      'INPUT_API-KEY': process.env.API_KEY,
      'INPUT_ORG-ID': process.env.ORG_ID,
      'INPUT_BOUNDARY-ID': process.env.BOUNDARY_ID,
      'INPUT_URL': process.env.URL,
      'INPUT_PACKAGE': '@auditmation/file-service-app@latest',
      'INPUT_FILE-PATH': 'bom.json',
      'INPUT_PRODUCT-ID': process.env.PRODUCT_ID,
      ...process.env,
    };

    // Note: We're executing the compiled dist/index.js, not the TS source
    const indexPath = path.join(dirname, '..', 'dist', 'index.js');
    const exitCode = await exec.exec('node', [indexPath], { env });

    console.log('Exit code:', exitCode);
    expect(exitCode).to.equal(0);
  });
});
