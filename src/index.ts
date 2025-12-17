import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { newFileService } from '@auditmation/module-auditmation-auditmation-file-service';
import {
  newPlatform,
  PipelineAdminStatusEnum,
  PipelineFormatEnum,
  PipelineJobStatusEnum,
} from '@auditmation/module-auditmation-auditmation-platform';
import { TimeZone, URL, UUID } from '@auditmation/types-core-js';
import axios, { type AxiosInstance } from 'axios';
import * as fs from 'fs';
import md5File from 'md5-file';
import * as path from 'path';
import * as https from 'node:https';

// Type Interfaces
interface ActionInputs {
  productId: string;
  packageName: string;
  version: string;
  filePath: string;
  apiKey: string;
  orgId: string;
  url: URL;
  boundaryId: string;
}

interface ExtractedPackageInfo {
  pkgName: string;
  version: string;
  sbomFilePath: string;
  fileSize: number;
  checksum: string;
}

interface ApiClients {
  axios: AxiosInstance;
  fileService: any;
  platform: any;
}

interface Pipeline {
  id: string;
  name: string;
  productId: string;
  boundaryId: string;
  description: string;
  timezone: any;
  targets: Record<string, unknown>;
  moduleName: string;
  format: any;
  adminStatus: any;
}

interface PipelineJob {
  id: string;
}

interface Batch {
  id: string;
}

interface File {
  id: string;
  name: string;
  fileVersionId: string;
  checksum: string;
}

interface Folder {
  id: string;
  name: string;
}

interface BoundaryProduct {
  id: string;
  productId: string;
}

interface PackageJson {
  version: string;
}

interface FileUploadResponse {
  fileVersionId: string;
}

// Constants
const EVIDENCE_DEFINITION_ID = '209010da-70d1-5fa5-babf-91974fa13bd2' as const;
const PIPELINE_NAME = 'Auditmation SBOM Recorder' as const;

// Global error handlers
process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
  console.error('Unhandled Rejection at Promise:', promise);
  console.error('Reason:', reason);
});

process.on('uncaughtException', (err: Error) => {
  console.error('Uncaught Exception thrown:', err);
  process.exit(1);
});

// Helper Functions
async function parseActionInputs(): Promise<ActionInputs> {
  const productId = core.getInput('product-id');
  const packageInput = core.getInput('package');
  const vIndex = packageInput.indexOf('@', 1);

  if (vIndex === -1) {
    throw new Error('Invalid package format. Expected @scope/package@version');
  }

  let version = packageInput.substring(vIndex + 1);
  const packageName = packageInput.substring(0, vIndex);
  const filePath = core.getInput('file-path');
  const apiKey = core.getInput('api-key');
  const orgId = core.getInput('org-id');

  const urlInput = core.getInput('url');
  let url = await URL.parse(urlInput);
  const hostname = url.hostname.startsWith('api')
    ? url.hostname
    : `api.${url.hostname}`;
  url = await URL.parse(`${url.protocol}://${hostname}`);

  const boundaryId = core.getInput('boundary-id');

  return {
    productId,
    packageName,
    version,
    filePath,
    apiKey,
    orgId,
    url,
    boundaryId,
  };
}

async function downloadAndExtractPackage(
  inputs: ActionInputs
): Promise<ExtractedPackageInfo> {
  const { packageName, version: inputVersion, filePath } = inputs;

  // Download package using npm pack
  let fileName = '';
  await exec.exec('npm', ['--silent', 'pack', `${packageName}@${inputVersion}`], {
    listeners: {
      stdout: (data: Buffer) => {
        fileName += data.toString();
      },
    },
    cwd: process.cwd(),
  });

  fileName = fileName.trim();

  // Extract package
  await exec.exec('sh', ['-c', `tar zxf ${fileName}`]);

  // Get current directory
  let out = '';
  const options: exec.ExecOptions = {
    listeners: {
      stdout: (data: Buffer) => {
        out += data.toString();
      },
    },
  };
  await exec.exec('pwd', [], options);
  const cwd = out.trim();

  // Construct SBOM file path
  const sbomFilePath = path.join(cwd, 'package', filePath);

  // Resolve actual version if 'latest' was specified
  let version = inputVersion;
  if (version === 'latest') {
    const pkgJsonPath = path.join(cwd, 'package', 'package.json');
    const pkgJsonContent = fs.readFileSync(pkgJsonPath, 'utf-8');
    const pkgJson = JSON.parse(pkgJsonContent) as PackageJson;
    version = pkgJson.version;
  }

  // Verify SBOM file exists
  if (!fs.existsSync(sbomFilePath)) {
    throw new Error(`SBOM file not found: ${sbomFilePath}`);
  }

  // Get file stats and checksum
  const stat = fs.statSync(sbomFilePath);
  const checksum = md5File.sync(sbomFilePath);

  return {
    pkgName: packageName,
    version,
    sbomFilePath,
    fileSize: stat.size,
    checksum,
  };
}

async function setupApiClients(inputs: ActionInputs): Promise<ApiClients> {
  const { url, apiKey, orgId } = inputs;

  const axiosInstance = axios.create({
    baseURL: url.toString(),
    headers: {
      Authorization: `APIKey ${apiKey}`,
      'dana-org-id': orgId.toString(),
    },
  });

  const fileService = newFileService();
  await fileService.connect({
    apiKey,
    orgId: await UUID.parse(orgId),
    url: await URL.parse(`${url.toString()}file-service`),
  });

  const platform = newPlatform();
  await platform.connect({
    apiKey,
    orgId: await UUID.parse(orgId),
    url: await URL.parse(`${url.toString()}platform`),
  });

  return {
    axios: axiosInstance,
    fileService,
    platform,
  };
}

async function ensureBoundary(
  clients: ApiClients,
  inputs: ActionInputs
): Promise<string> {
  const { platform } = clients;
  let { boundaryId } = inputs;

  // Get or create boundary
  if (!boundaryId) {
    const boundaries = await platform.getBoundaryApi().listBoundaries();
    boundaryId = boundaries.items[0].id;
  }
  console.log('Using boundary:', boundaryId);

  return boundaryId;
}

async function ensureBoundaryProduct(
  clients: ApiClients,
  boundaryId: string,
  productId: string
): Promise<string> {
  const { platform } = clients;

  // Create boundary product (may already exist)
  await platform.getBoundaryApi().createBoundaryProduct(boundaryId, {
    name: 'Auditmation',
    description: '',
    productIds: [productId],
  });

  // Find the boundary product ID
  const boundaryProductsResponse = await platform
    .getBoundaryApi()
    .listBoundaryProductsByBoundary(boundaryId);

  const boundaryProduct = boundaryProductsResponse.items.find(
    (product: BoundaryProduct) => product.productId.toString() === productId
  );

  if (!boundaryProduct) {
    throw new Error(`Boundary product not found for product ID: ${productId}`);
  }

  console.log('Boundary product:', boundaryProduct.id);
  return boundaryProduct.id;
}

async function ensurePipeline(
  clients: ApiClients,
  boundaryId: string,
  productId: string,
  packageInfo: ExtractedPackageInfo
): Promise<Pipeline> {
  const { platform } = clients;
  const filePrefix = packageInfo.pkgName.replace('@', '').replace('/', '-');

  // Check if pipeline already exists
  const pipelines = await platform.getPipelineApi().getAllPipelines(
    undefined,
    undefined,
    [PIPELINE_NAME],
    boundaryId,
    productId,
    PipelineAdminStatusEnum.On,
  );

  let pipeline: Pipeline;
  if (pipelines.items.length === 0) {
    pipeline = await platform.getPipelineApi().createPipeline({
      name: PIPELINE_NAME,
      productId,
      boundaryId,
      description: `Auto generated pipeline from ${filePrefix} SBOMs`,
      timezone: TimeZone.Utc,
      targets: {},
      moduleName: 'Auditmation',
      format: PipelineFormatEnum.File,
    });
  } else {
    [pipeline] = pipelines.items;
  }

  // Ensure pipeline is enabled
  pipeline.adminStatus = PipelineAdminStatusEnum.On;
  pipeline = await platform.getPipelineApi().updatePipeline(pipeline.id, pipeline);

  console.log('Using pipeline:', pipeline.id);
  return pipeline;
}

async function createPipelineJob(
  clients: ApiClients,
  pipelineId: string
): Promise<PipelineJob> {
  const { platform } = clients;

  const job = await platform.getPipelineJobApi().createPipelineJob({
    pipelineId,
    previewMode: false,
  });

  console.log('Created job:', job.id);
  return job;
}

async function createBatch(
  clients: ApiClients,
  jobId: string,
  groupId: string
): Promise<Batch> {
  const { platform } = clients;

  const batch = await platform.getBatchApi().createBatch({
    className: 'EvidenceFile',
    jobId,
    groupId,
  });

  console.log('Created batch:', batch.id);
  return batch;
}

async function ensureFolderStructure(
  fileService: any,
  pipelineId: string
): Promise<string> {
  // Ensure /pipeline folder exists
  let foldersResponse = await fileService.getResourceApi().searchResources(
    undefined,
    undefined,
    ['pipeline'],
    undefined,
    ['folder'],
  );

  let pipelineFolderId = foldersResponse.items?.find((f: Folder) => f.name === 'pipeline')?.id;

  if (!pipelineFolderId) {
    const folder = await fileService.getFolderApi().create({
      name: 'pipeline',
    }) as Folder;
    pipelineFolderId = folder.id;
  }

  // Ensure /pipeline/{pipelineId} folder exists
  foldersResponse = await fileService.getResourceApi().searchResources(
    undefined,
    undefined,
    [pipelineId.toString()],
    undefined,
    ['folder'],
  );

  let folderId = foldersResponse.items?.find((f: Folder) => f.name === pipelineId.toString())?.id;

  if (!folderId) {
    const folder = await fileService.getFolderApi().create({
      name: pipelineId.toString(),
      folderId: pipelineFolderId.toString(),
    }) as Folder;
    folderId = folder.id;
  }

  return folderId;
}

async function uploadFileContents(
  url: URL,
  apiKey: string,
  orgId: string,
  fileId: string,
  filePath: string,
  fileSize: number,
  checksum: string
): Promise<string> {
  return new Promise((resolve, reject) => {
    const fileStream = fs.createReadStream(filePath);

    const opts: https.RequestOptions = {
      hostname: url.hostname,
      port: url.port,
      path: `/file-service/files/${fileId}/upload?checksum=${checksum}`,
      method: 'POST',
      protocol: 'https:',
      headers: {
        'content-length': fileSize.toString(),
        'content-type': 'application/json',
        Authorization: `APIKey ${apiKey}`,
        'dana-org-id': orgId.toString(),
      },
    };

    let responseData = '';

    const req = https.request(opts, (res) => {
      res.on('data', (chunk: Buffer) => {
        const chunkStr = chunk.toString();
        console.log('Upload chunk received:', chunkStr);
        responseData += chunkStr;
      });

      res.on('end', () => {
        console.log('File upload completed');
        try {
          const data = JSON.parse(responseData) as FileUploadResponse;
          resolve(data.fileVersionId);
        } catch (error) {
          reject(new Error(`Failed to parse upload response: ${responseData}`));
        }
      });
    });

    req.on('error', (err: Error) => {
      console.error(`Error uploading file: ${err.message}`);
      reject(err);
    });

    fileStream.pipe(req);
  });
}

async function uploadSbomFile(
  clients: ApiClients,
  pipelineId: string,
  packageInfo: ExtractedPackageInfo,
  inputs: ActionInputs
): Promise<File> {
  const { fileService } = clients;
  const { sbomFilePath, pkgName, version, fileSize, checksum } = packageInfo;

  // Ensure folder structure exists
  const folderId = await ensureFolderStructure(fileService, pipelineId);

  // Create file record
  const file = await fileService.getFileApi().create({
    name: `${pkgName}-${version}.json`,
    description: `SBOM for ${pkgName}`,
    folderId,
    retentionPolicy: {},
    syncPolicy: {},
  }) as File;

  console.log('File:', file.id);
  let fileVersionId = file.fileVersionId.toString();

  // Upload file contents if checksum differs
  if (checksum !== file.checksum) {
    fileVersionId = await uploadFileContents(
      inputs.url,
      inputs.apiKey,
      inputs.orgId,
      file.id,
      sbomFilePath,
      fileSize,
      checksum
    );
    console.log('File uploaded with new version:', fileVersionId);
  } else {
    console.log('File checksum matches, skipping upload');
  }

  return {
    ...file,
    fileVersionId,
  };
}

async function addBatchItem(
  clients: ApiClients,
  batchId: string,
  file: File,
  pipelineId: string,
  fileSize: number
): Promise<void> {
  const { platform } = clients;

  const batchItem = await platform.getBatchApi().addBatchItem(batchId, {
    payload: {
      id: file.id,
      name: file.name,
      fileVersionId: file.fileVersionId,
      size: fileSize,
      mimeType: 'application/json',
      evidenceDefinition: EVIDENCE_DEFINITION_ID,
      pipelineId,
    },
    rawData: {},
  });

  console.log('Batch item:', batchItem.id);
}

async function completePipelineJob(
  clients: ApiClients,
  jobId: string
): Promise<void> {
  const { platform } = clients;

  await platform.getPipelineJobApi().updatePipelineJob(jobId, {
    status: PipelineJobStatusEnum.Completed,
  });
}

async function closeBatch(
  clients: ApiClients,
  batchId: string
): Promise<void> {
  const { platform } = clients;

  await platform.getBatchApi().endBatch(batchId);
}

// Main function
async function run(): Promise<void> {
  try {
    // Parse inputs
    const inputs = await parseActionInputs();

    // Download and extract package
    const packageInfo = await downloadAndExtractPackage(inputs);

    // Setup API clients
    const clients = await setupApiClients(inputs);

    // Get or create boundary
    const boundaryId = await ensureBoundary(clients, inputs);

    // Create boundary product
    await ensureBoundaryProduct(clients, boundaryId, inputs.productId);

    // Get or create pipeline
    const pipeline = await ensurePipeline(
      clients,
      boundaryId,
      inputs.productId,
      packageInfo
    );

    // Create job and batch
    const job = await createPipelineJob(clients, pipeline.id);
    const batch = await createBatch(clients, job.id, packageInfo.pkgName);

    // Upload file
    const file = await uploadSbomFile(
      clients,
      pipeline.id,
      packageInfo,
      inputs
    );

    // Add batch item and complete
    await addBatchItem(clients, batch.id, file, pipeline.id, packageInfo.fileSize);
    await completePipelineJob(clients, job.id);
    await closeBatch(clients, batch.id);

    console.log('SBOM upload completed successfully');
  } catch (error) {
    const err = error as Error;
    console.error('Error:', err.message);
    console.error('Stack:', err.stack);
    core.setFailed(err.message);
    process.exit(1);
  }
}

// Entry point
run().catch((error: Error) => {
  console.error('Unhandled error in run():', error);
  process.exit(1);
});