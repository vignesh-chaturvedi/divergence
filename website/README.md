# Divergence website

The marketing and quickstart site is an Astro static build kept inside the main Divergence
repository. It has no API routes, secrets, database, or hosted scanning functionality.

## Local development

Node 22 is the deployment runtime.

```bash
cd website
npm ci
npm run dev
```

Quality checks:

```bash
npm run check
npm run build
npm run preview
```

## Deploy on Vercel

Import `vignesh-chaturvedi/divergence` as a Vercel project and set:

- Root Directory: `website`
- Framework Preset: Astro
- Install Command: `npm ci`
- Build Command: `npm run build`
- Output Directory: `dist`
- Production Branch: `main`

No environment variables are required. `vercel.json` adds conservative response headers.
Add the production domain to `astro.config.mjs` and the page metadata after Vercel assigns
the stable URL. Add the separate `website` GitHub Actions check to the `main` branch
ruleset alongside `scan` and `sandbox`.
