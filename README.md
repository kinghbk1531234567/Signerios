# iOS Web Signer

Minimal Render-hosted IPA signer using zsign.

## Deploy

1. Create a GitHub repository and upload these files.
2. In Render: New -> Web Service.
3. Connect the repository.
4. Runtime/Language: Docker.
5. Create the service.
6. Open the generated HTTPS `onrender.com` URL on the iPhone/iPad.
7. Pick the IPA, `.p12`, `.mobileprovision`, type the P12 password, and tap **Sign & Install**.

Optional environment variables:

- `BASE_URL=https://your-domain.example` if you want to force a public base URL.
- `JOB_TTL_MS=1800000` signed IPA lifetime in milliseconds (default 30 minutes).
- `MAX_UPLOAD_BYTES=2147483648` maximum size per uploaded file.

## Important iOS requirement

The website cannot bypass Apple's signing/provisioning rules. The certificate/profile must authorize the app and target device. Apple's documented website OTA flow is for properly signed/provisioned in-house apps. Ad Hoc/development profiles require registered devices.
