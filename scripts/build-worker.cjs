#!/usr/bin/env node

const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const TOOLCHAIN = '1.88.0';
const TARGET = 'wasm32-unknown-unknown';
const WORKER_BUILD_VERSION = '0.8.5';
const RUSTUP_URL = 'https://sh.rustup.rs';
const MAX_DOWNLOAD_BYTES = 1024 * 1024;

const projectRoot = path.resolve(__dirname, '..');
const cargoHome = process.env.CARGO_HOME || path.join(os.homedir(), '.cargo');
const rustupHome = process.env.RUSTUP_HOME || path.join(os.homedir(), '.rustup');
const commandEnv = {
  ...process.env,
  CARGO_HOME: cargoHome,
  RUSTUP_HOME: rustupHome,
  PATH: `${path.join(cargoHome, 'bin')}${path.delimiter}${process.env.PATH || ''}`,
};

function run(command, args, options = {}) {
  const capture = options.capture === true;
  const result = spawnSync(command, args, {
    cwd: options.cwd || projectRoot,
    env: commandEnv,
    encoding: 'utf8',
    stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const detail = capture ? `\n${result.stderr || result.stdout || ''}` : '';
    throw new Error(`${command} exited with status ${result.status}${detail}`);
  }
  return capture ? (result.stdout || '').trim() : '';
}

function commandWorks(command, args = ['--version']) {
  const result = spawnSync(command, args, {
    cwd: projectRoot,
    env: commandEnv,
    stdio: 'ignore',
  });
  return !result.error && result.status === 0;
}

function downloadHttps(url, destination, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) {
      reject(new Error(`Too many redirects while downloading ${RUSTUP_URL}`));
      return;
    }

    const request = https.get(url, { headers: { 'user-agent': 'SuperDoH-build' } }, (response) => {
      const status = response.statusCode || 0;
      if (status >= 300 && status < 400 && response.headers.location) {
        response.resume();
        const redirected = new URL(response.headers.location, url);
        if (redirected.protocol !== 'https:') {
          reject(new Error(`Refusing non-HTTPS redirect to ${redirected.href}`));
          return;
        }
        downloadHttps(redirected.href, destination, redirects + 1).then(resolve, reject);
        return;
      }
      if (status !== 200) {
        response.resume();
        reject(new Error(`Failed to download rustup installer: HTTP ${status}`));
        return;
      }

      let bytes = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > MAX_DOWNLOAD_BYTES) {
          request.destroy(new Error('rustup installer exceeded the download limit'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        fs.writeFileSync(destination, Buffer.concat(chunks), { mode: 0o700 });
        resolve();
      });
    });
    request.on('error', reject);
  });
}

async function ensureRustup() {
  if (commandWorks('rustup')) {
    return;
  }
  if (process.platform === 'win32') {
    throw new Error('rustup is required on Windows. Install it from https://rustup.rs first.');
  }

  console.log(`rustup not found; installing Rust ${TOOLCHAIN} with the minimal profile...`);
  const installer = path.join(os.tmpdir(), `superdoh-rustup-${process.pid}.sh`);
  try {
    await downloadHttps(RUSTUP_URL, installer);
    run('sh', [
      installer,
      '-y',
      '--profile',
      'minimal',
      '--default-toolchain',
      TOOLCHAIN,
      '--no-modify-path',
    ]);
  } finally {
    fs.rmSync(installer, { force: true });
  }
}

function ensureToolchain() {
  const toolchains = run('rustup', ['toolchain', 'list'], { capture: true });
  if (!toolchains.split('\n').some((line) => line.startsWith(`${TOOLCHAIN}-`))) {
    console.log(`Installing Rust toolchain ${TOOLCHAIN}...`);
    run('rustup', ['toolchain', 'install', TOOLCHAIN, '--profile', 'minimal']);
  }

  const targets = run(
    'rustup',
    ['target', 'list', '--installed', '--toolchain', TOOLCHAIN],
    { capture: true },
  );
  if (!targets.split('\n').includes(TARGET)) {
    console.log(`Installing Rust target ${TARGET}...`);
    run('rustup', ['target', 'add', TARGET, '--toolchain', TOOLCHAIN]);
  }

  const components = run(
    'rustup',
    ['component', 'list', '--installed', '--toolchain', TOOLCHAIN],
    { capture: true },
  );
  if (!components.split('\n').some((line) => line.startsWith('rustfmt-'))) {
    console.log('Installing rustfmt...');
    run('rustup', ['component', 'add', 'rustfmt', '--toolchain', TOOLCHAIN]);
  }
}

function ensureWorkerBuild() {
  let installedVersion = '';
  if (commandWorks('worker-build')) {
    installedVersion = run('worker-build', ['--version'], { capture: true });
  }
  if (!installedVersion.includes(WORKER_BUILD_VERSION)) {
    console.log(`Installing worker-build ${WORKER_BUILD_VERSION}...`);
    run('cargo', [
      `+${TOOLCHAIN}`,
      'install',
      'worker-build',
      '--version',
      WORKER_BUILD_VERSION,
      '--locked',
    ]);
  }
}

async function main() {
  await ensureRustup();
  ensureToolchain();
  ensureWorkerBuild();

  console.log('Generating Rust configuration...');
  run(process.execPath, ['scripts/build-config.cjs']);

  console.log('Building Cloudflare Worker...');
  run('worker-build', ['--release', '--no-panic-recovery']);
}

main().catch((error) => {
  console.error(`Build failed: ${error.message}`);
  process.exitCode = 1;
});
