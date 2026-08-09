const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const app = express();
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 10000);
const ROOT = path.join(os.tmpdir(), 'ios-web-signer');
const JOBS = path.join(ROOT, 'jobs');
const JOB_TTL_MS = Number(process.env.JOB_TTL_MS || 30 * 60 * 1000);
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES || 2 * 1024 * 1024 * 1024);

fs.mkdirSync(JOBS, { recursive: true });

function id() {
  return crypto.randomBytes(16).toString('hex');
}

function xmlEscape(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function publicBase(req) {
  const configured = (process.env.BASE_URL || '').trim().replace(/\/$/, '');
  if (configured) return configured;
  return `${req.protocol}://${req.get('host')}`;
}

async function removeDir(dir) {
  try {
    await fsp.rm(dir, { recursive: true, force: true });
  } catch (_) {}
}

async function readAppMetadata(ipaPath, jobDir) {
  const { stdout: listing } = await execFileAsync('unzip', ['-Z1', ipaPath], {
    maxBuffer: 16 * 1024 * 1024
  });

  const infoEntry = listing
    .split(/\r?\n/)
    .find((line) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(line));

  if (!infoEntry) {
    throw new Error('Could not find Payload/*.app/Info.plist in this IPA.');
  }

  const infoPath = path.join(jobDir, 'Info.plist');
  await new Promise((resolve, reject) => {
    const child = execFile('unzip', ['-p', ipaPath, infoEntry], { encoding: 'buffer', maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
      if (err) return reject(err);
      fs.writeFile(infoPath, stdout, (writeErr) => writeErr ? reject(writeErr) : resolve());
    });
    child.stdin?.end();
  });

  const py = `import json, plistlib, sys; p=plistlib.load(open(sys.argv[1], "rb")); print(json.dumps({"bundleId": p.get("CFBundleIdentifier", ""), "version": p.get("CFBundleShortVersionString") or p.get("CFBundleVersion") or "1.0", "build": p.get("CFBundleVersion") or "1", "name": p.get("CFBundleDisplayName") or p.get("CFBundleName") or "Signed App"}))`;

  const { stdout } = await execFileAsync('python3', ['-c', py, infoPath], {
    maxBuffer: 1024 * 1024
  });

  const data = JSON.parse(stdout);
  if (!data.bundleId) throw new Error('The IPA has no CFBundleIdentifier.');
  return data;
}

function makeUpload() {
  const storage = multer.diskStorage({
    destination(req, file, cb) {
      cb(null, req.jobDir);
    },
    filename(req, file, cb) {
      const map = {
        ipa: 'input.ipa',
        p12: 'certificate.p12',
        profile: 'profile.mobileprovision'
      };
      cb(null, map[file.fieldname] || `${id()}.bin`);
    }
  });

  return multer({
    storage,
    limits: {
      fileSize: MAX_UPLOAD_BYTES,
      files: 3,
      fields: 10
    }
  }).fields([
    { name: 'ipa', maxCount: 1 },
    { name: 'p12', maxCount: 1 },
    { name: 'profile', maxCount: 1 }
  ]);
}

const upload = makeUpload();

app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  maxAge: '5m'
}));

app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.post('/api/sign', async (req, res) => {
  const jobId = id();
  const jobDir = path.join(JOBS, jobId);
  req.jobDir = jobDir;
  await fsp.mkdir(jobDir, { recursive: true });

  upload(req, res, async (uploadErr) => {
    if (uploadErr) {
      await removeDir(jobDir);
      return res.status(400).json({ error: uploadErr.message || 'Upload failed.' });
    }

    try {
      const ipa = req.files?.ipa?.[0]?.path;
      const p12 = req.files?.p12?.[0]?.path;
      const profile = req.files?.profile?.[0]?.path;
      const password = String(req.body?.password ?? '');

      if (!ipa || !p12 || !profile) {
        throw new Error('Choose an IPA, P12 certificate, and mobileprovision file.');
      }

      const before = await readAppMetadata(ipa, jobDir);
      const signedIpa = path.join(jobDir, 'signed.ipa');

      // IMPORTANT: use execFile, not a shell command. This prevents filenames/passwords
      // from being interpreted as shell syntax.
      await execFileAsync('zsign', [
        '-f',
        '-k', p12,
        '-p', password,
        '-m', profile,
        '-o', signedIpa,
        ipa
      ], {
        maxBuffer: 32 * 1024 * 1024,
        timeout: 20 * 60 * 1000
      });

      if (!fs.existsSync(signedIpa)) {
        throw new Error('Signing finished but no signed IPA was produced.');
      }

      const after = await readAppMetadata(signedIpa, jobDir);
      const meta = {
        id: jobId,
        bundleId: after.bundleId || before.bundleId,
        version: after.version || before.version || '1.0',
        build: after.build || before.build || '1',
        name: after.name || before.name || 'Signed App',
        createdAt: Date.now()
      };

      await fsp.writeFile(path.join(jobDir, 'meta.json'), JSON.stringify(meta), 'utf8');

      // Remove the user's private signing material as soon as signing is complete.
      await Promise.allSettled([
        fsp.rm(p12, { force: true }),
        fsp.rm(profile, { force: true }),
        fsp.rm(ipa, { force: true }),
        fsp.rm(path.join(jobDir, 'Info.plist'), { force: true })
      ]);

      const base = publicBase(req);
      const manifestUrl = `${base}/install/${jobId}/manifest.plist`;
      const installUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;

      res.json({
        ok: true,
        app: {
          name: meta.name,
          bundleId: meta.bundleId,
          version: meta.version
        },
        installUrl,
        ipaUrl: `${base}/install/${jobId}/app.ipa`
      });
    } catch (err) {
      console.error('Signing error:', err?.message || err);
      await removeDir(jobDir);
      res.status(400).json({
        error: err?.stderr?.toString()?.trim() || err?.message || 'Signing failed.'
      });
    }
  });
});

app.get('/install/:id/manifest.plist', async (req, res) => {
  try {
    if (!/^[a-f0-9]{32}$/.test(req.params.id)) return res.sendStatus(404);
    const jobDir = path.join(JOBS, req.params.id);
    const meta = JSON.parse(await fsp.readFile(path.join(jobDir, 'meta.json'), 'utf8'));
    const signedIpa = path.join(jobDir, 'signed.ipa');
    if (!fs.existsSync(signedIpa)) return res.sendStatus(404);

    const ipaUrl = `${publicBase(req)}/install/${req.params.id}/app.ipa`;
    const manifest = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key>
          <string>software-package</string>
          <key>url</key>
          <string>${xmlEscape(ipaUrl)}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key>
        <string>${xmlEscape(meta.bundleId)}</string>
        <key>bundle-version</key>
        <string>${xmlEscape(meta.build || meta.version || '1')}</string>
        <key>kind</key>
        <string>software</string>
        <key>title</key>
        <string>${xmlEscape(meta.name || 'Signed App')}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>`;

    res.set({
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'no-store'
    });
    res.send(manifest);
  } catch (_) {
    res.sendStatus(404);
  }
});

app.get('/install/:id/app.ipa', async (req, res) => {
  if (!/^[a-f0-9]{32}$/.test(req.params.id)) return res.sendStatus(404);
  const file = path.join(JOBS, req.params.id, 'signed.ipa');
  if (!fs.existsSync(file)) return res.sendStatus(404);

  res.set({
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': 'attachment; filename="signed.ipa"',
    'Cache-Control': 'no-store'
  });
  res.sendFile(file);
});

async function cleanupOldJobs() {
  try {
    const entries = await fsp.readdir(JOBS, { withFileTypes: true });
    const now = Date.now();
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const dir = path.join(JOBS, entry.name);
      try {
        const stat = await fsp.stat(dir);
        if (now - stat.mtimeMs > JOB_TTL_MS) await removeDir(dir);
      } catch (_) {}
    }
  } catch (_) {}
}

setInterval(cleanupOldJobs, 5 * 60 * 1000).unref();
cleanupOldJobs();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`iOS Web Signer listening on 0.0.0.0:${PORT}`);
});
