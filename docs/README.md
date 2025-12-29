# Security Scanner MCP Documentation

This directory contains the documentation website for Security Scanner MCP, built with [Docusaurus](https://docusaurus.io/).

## Quick Start

### Installation

```bash
npm install
```

### Local Development

```bash
npm start
```

This command starts a local development server and opens a browser window. Most changes are reflected live without having to restart the server.

### Build

```bash
npm run build
```

This command generates static content into the `build` directory that can be served using any static hosting service.

### Serve Build Locally

```bash
npm run serve
```

Test the production build locally.

## Documentation Structure

```
docs/
├── docs/                    # Documentation markdown files
│   ├── intro.md            # Introduction
│   ├── installation.md     # Installation guide
│   ├── quick-start.md      # Quick start guide
│   ├── features/           # Feature documentation
│   ├── usage/              # Usage guides
│   ├── advanced/           # Advanced topics
│   └── reference/          # API and configuration reference
├── src/                    # Custom React components
│   └── pages/              # Custom pages
├── static/                 # Static assets (images, favicons)
└── docusaurus.config.ts   # Site configuration
```

## Multi-language Support

The site is configured for multi-language support:
- English (default)
- Korean (todo)
- Japanese (todo)
- Chinese (todo)

To add translations, create files in `i18n/{locale}/docusaurus-plugin-content-docs/current/`.

## Deployment

The documentation is automatically deployed to GitHub Pages via GitHub Actions when changes are pushed to the main branch.

See `.github/workflows/deploy-docs.yml` for the deployment configuration.

## Learn More

- [Docusaurus Documentation](https://docusaurus.io/)
- [Markdown Features](https://docusaurus.io/docs/markdown-features)
