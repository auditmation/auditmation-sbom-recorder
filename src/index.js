const core = require('@actions/core');

const fs = require('fs');
const md5File = require('md5-file');
const path = require('path');

const { newFileService } = require('@auditmation/module-auditmation-auditmation-file-service');
const { newPlatform, PipelineAdminStatusEnum, PipelineFormatEnum, PipelineJobStatusEnum } = require('@auditmation/module-auditmation-auditmation-platform');

process
  .on('unhandledRejection', (reason, p) => {
    console.error(reason, 'Unhandled Rejection at Promise', p);
  })
  .on('uncaughtException', (err) => {
    console.error(err, 'Uncaught Exception thrown');
    process.exit(1);
  });

const evidenceDefinitionId = '209010da-70d1-5fa5-babf-91974fa13bd2';
const productId = '6a70bddd-99ae-5275-95a5-4244a4228092';

async function run() {
  try {
    const pkgName = core.getInput('package');
    const filePath = core.getInput('file-path');
    const apiKey = core.getInput('api-key');
    const orgId = core.getInput('org-id');
    let url = await URL.parse(core.getInput('url'));
    const hostname = url.hostname.startsWith('api') ? url.hostname: `api.${url.hostname}`;
    url = await URL.parse(`${url.protocol}://${hostname}`);
    let boundaryId = core.getInput('boundary-id');

    let fileName = '';
    const out = await exec.exec('npm', ['pack', pkgName], {
      listeners: {
        stdout: (data) => {
          fileName += data.toString();
        },
      },
      cwd: process.cwd(),
    });
    const filePrefix = pkgName.replace('@', '').replace('/', '-');
    await exec.exec('sh -c', [`tar zxfv ${fileName}`], {
      cwd: process.cwd(),
    });
    console.log(__dirname);
    console.log(process.cwd());
    const sbomFilePath = path.join(__dirname, '..', 'package', filePath);
    if (!fs.existsSync(sbomFilePath)) {
      throw new Error(`File not found: ${sbomFilePath}`);
    }

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
      orgId,
      url: await URL.parse(`${url.toString()}file-service`),
    });

    const platform = newPlatform();
    await platform.connect({
      apiKey,
      orgId,
      url: await URL.parse(`${url.toString()}platform`),
    });

    // Get or create boundary?
    if (!boundaryId) {
      const boundaries = await platform.getBoundaryApi().listBoundaries();
      boundaryId = boundaries.items[0].id;
    }
    console.log('Using boundary:', boundaryId);

    // Find the product
    await platform.getBoundaryApi().createBoundaryProduct(boundaryId, {
      name: 'npm',
      description: '',
      productIds: [productId],
    });

    let boundaryProductId;
    const boundaryProducts = await platform.getBoundaryApi().listBoundaryProductsByBoundary(boundaryId);
    await boundaryProducts.forEach((product) => {
      if (product.productId.toString() === productId) {
        boundaryProductId = product.id;
      }
    });
    console.log('Boundary product:', boundaryProductId);

    // Create a pipeline
    const pipelines = await platform.getPipelineApi().getAllPipelines(
      undefined,
      undefined,
      [filePrefix],
      boundaryId,
      productId,
      PipelineAdminStatusEnum.On,
    );

    let pipeline;
    if (pipelines.items.length === 0) {
      pipeline = await platform.getPipelineApi().createPipeline({
        name: `SBOM - ${filePrefix}`,
        productId,
        boundaryId,
        description: `Auto generated pipeline from ${filePrefix} SBOMs`,
        timezone: TimeZone.Utc,
        targets: {},
        moduleName: 'npm',
        format: PipelineFormatEnum.File,
      });
    } else {
      [pipeline] = pipelines.items;
    }
    // console.log('Pipeline', pipeline);
    const pipelineId = pipeline.id;
    pipeline.adminStatus = PipelineAdminStatusEnum.On;
    pipeline = await platform.getPipelineApi().updatePipeline(pipelineId, pipeline);

    console.log('Using pipeline:', pipelineId);

    // create pipeline job
    const job = await platform.getPipelineJobApi().createPipelineJob({
      pipelineId,
      previewMode: false,
    });
    const jobId = job.id;
    console.log('Created job:', jobId);

    // create a batch
    const batch = await platform.getBatchApi().createBatch({
      className: 'EvidenceFile',
      jobId,
      groupId: pipelineId,
    });
    const batchId = batch.id;
    console.log('Created batch:', batchId);

    // ensure a folder
    const uploadPath = `/pipeline/${pipelineId}`;
    let pipelineFolderId;

    let folders = await fileService.getResourceApi().searchResources(
      undefined,
      undefined,
      ['pipeline'],
      undefined,
      ['folder'],
    );

    await folders.forEach((folder) => {
      if (folder.name === 'pipeline') {
        pipelineFolderId = folder.id;
      }
    });

    if (!pipelineFolderId) {
      const folder = await fileService.getFolderApi().create({
        name: 'pipeline',
      });
      pipelineFolderId = folder.id;
    }

    folders = await fileService.getResourceApi().searchResources(
      undefined,
      undefined,
      [pipelineId.toString()],
      undefined,
      ['folder'],
    );

    let folderId;
    await folders.forEach((folder) => {
      if (folder.name === pipelineId.toString()) {
        folderId = folder.id;
      }
    });

    if (!folderId) {
      const folder = await fileService.getFolderApi().create({
        name: pipelineId.toString(),
        folderId: pipelineFolderId.toString(),
      });
      folderId = folder.id;
    }

    const file = await fileService.getFileApi().create({
      name: 'bom.json',
      description: `SBOM for ${pkgName}`,
      folderId,
      retentionPolicy: {},
      syncPolicy: {},
    });
    console.log('File:', file.id);
    let fileVersionId = file.fileVersionId.toString();

    // upload a file
    const fileStream = fs.createReadStream(sbomFilePath);
    const stat = fs.statSync(sbomFilePath);
    const checksum = md5File.sync(sbomFilePath);
    if (checksum !== file.checksum) {
      const out = await axiosInstance.post(`/file-service/files/${file.id}/upload?checksum=${checksum}`, {
        headers: {
          'content-length': stat.size,
          'content-type': 'application/json',
        },
        data: fileStream,
      });
      console.log('Upload', out.data);
      fileVersionId = out.data.fileVersionId;
    }
    console.log('File version id:', fileVersionId);

    // add a batch item
    const batchItem = await platform.getBatchApi().addBatchItem(batchId, {
      payload: {
        id: file.id,
        name: file.name,
        fileVersionId,
        size: stat.size,
        mimeType: 'application/json',
        evidenceDefinition: evidenceDefinitionId,
        pipelineId,
      },
      rawData: {},
    });
    console.log('Batch item:', batchItem.id);

    await platform.getPipelineJobApi().updatePipelineJob(jobId, {
      status: PipelineJobStatusEnum.Completed,
    });

    // close the batch
    await platform.getBatchApi().endBatch(batchId);
  } catch (err) {
    console.log(err);
    console.log(err.stack);
    process.exit(1);
  }
}

run();
