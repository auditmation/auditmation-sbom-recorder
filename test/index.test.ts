import * as exec from '@actions/exec';
import { expect } from 'chai';
import path from 'node:path';
import { config } from 'dotenv';
import { existsSync } from 'node:fs';

// Load .env file if it exists
const envPath = path.join(import.meta.dirname, '..', '.env');
if (existsSync(envPath)) {
  config({ path: envPath });
}

describe('Auditmation SBOM Recorder Test', function () {
  it('Should upload an sbom from an artifact', async function () {
    // Helper to get env var with or without INPUT_ prefix
    const getEnvVar = (name: string): string | undefined => {
      return process.env[`INPUT_${name}`] || process.env[name];
    };

    // Check if required environment variables are present
    const requiredVars = ['API-KEY', 'ORG-ID', 'URL', 'BOUNDARY-ID', 'PRODUCT-ID'];
    const missingVars = requiredVars.filter((v) => !getEnvVar(v));
    if (missingVars.length > 0) {
      console.log(`Skipping test: Missing required environment variables (${missingVars.join(', ')})`);
      this.skip();
      return;
    }

    const env: { [key: string]: string } = {
      'INPUT_API-KEY': getEnvVar('API-KEY')!,
      'INPUT_ORG-ID': getEnvVar('ORG-ID')!,
      'INPUT_BOUNDARY-ID': getEnvVar('BOUNDARY-ID')!,
      'INPUT_URL': getEnvVar('URL')!,
      'INPUT_PACKAGE': getEnvVar('PACKAGE') || '@auditmation/file-service-app@latest',
      'INPUT_FILE-PATH': getEnvVar('FILE-PATH') || 'bom.json',
      'INPUT_PRODUCT-ID': getEnvVar('PRODUCT-ID')!,
      ...(process.env as { [key: string]: string }),
    };

    // Note: We're executing the compiled dist/index.js, not the TS source
    const indexPath = path.join(import.meta.dirname, '..', 'dist', 'index.js');
    const exitCode = await exec.exec('node', [indexPath], { env });

    console.log('Exit code:', exitCode);
    expect(exitCode).to.equal(0);
  });
});
