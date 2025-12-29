# Security Scanner MCP Documentation

This directory contains the Docusaurus documentation site for Security Scanner MCP.

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build

# Serve built site
npm run serve
```

## Development

The documentation supports 4 languages:
- English (default)
- 한국어 (Korean)
- 日本語 (Japanese) - Coming soon
- 简体中文 (Chinese) - Coming soon

### Start with specific locale

```bash
# Korean
npm run start -- --locale ko

# Japanese
npm run start -- --locale ja

# Chinese
npm run start -- --locale zh-CN
```

## Deployment

Documentation is automatically deployed to GitHub Pages when changes are pushed to the `main` branch.

URL: https://ongjin.github.io/security-scanner-mcp/

## Structure

```
docs/
├── docs/                    # English documentation
│   ├── intro.md
│   ├── installation.md
│   ├── quick-start.md
│   ├── features/
│   ├── usage/
│   ├── advanced/
│   └── reference/
├── i18n/                    # Translations
│   ├── ko/                  # Korean
│   ├── ja/                  # Japanese (TODO)
│   └── zh-CN/               # Chinese (TODO)
├── src/
│   ├── components/
│   ├── css/
│   └── pages/
└── static/
    └── img/
```

## Adding Translations

1. Create translation directory:
```bash
mkdir -p i18n/{locale}/docusaurus-plugin-content-docs/current
```

2. Translate markdown files to the new locale

3. Update `docusaurus.config.ts` if adding a new locale

## Contributing

Contributions are welcome! Please:
1. Follow the existing documentation structure
2. Maintain consistent formatting
3. Test locally before submitting
4. Update translations if modifying English docs
