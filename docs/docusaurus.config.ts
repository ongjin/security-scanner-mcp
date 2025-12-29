import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Security Scanner MCP',
  tagline: 'Your intelligent security partner for AI-generated code',
  favicon: 'img/favicon.ico',

  url: 'https://ongjin.github.io',
  baseUrl: '/security-scanner-mcp/',

  organizationName: 'ongjin',
  projectName: 'security-scanner-mcp',

  onBrokenLinks: 'throw',

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'], // TODO: Add 'ko', 'ja', 'zh-CN' after translations are complete
    localeConfigs: {
      en: {
        label: 'English',
        direction: 'ltr',
        htmlLang: 'en-US',
      },
      ko: {
        label: '한국어',
        direction: 'ltr',
        htmlLang: 'ko-KR',
      },
      ja: {
        label: '日本語',
        direction: 'ltr',
        htmlLang: 'ja-JP',
      },
      'zh-CN': {
        label: '简体中文',
        direction: 'ltr',
        htmlLang: 'zh-CN',
      },
    },
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/ongjin/security-scanner-mcp/tree/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/social-card.png',
    navbar: {
      title: 'Security Scanner MCP',
      logo: {
        alt: 'Security Scanner MCP Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'tutorialSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {
          href: 'https://github.com/ongjin/security-scanner-mcp',
          label: 'GitHub',
          position: 'right',
        },
        {
          type: 'localeDropdown',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/intro',
            },
            {
              label: 'Installation',
              to: '/docs/installation',
            },
            {
              label: 'Usage',
              to: '/docs/category/usage',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/ongjin/security-scanner-mcp',
            },
            {
              label: 'Issues',
              href: 'https://github.com/ongjin/security-scanner-mcp/issues',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'npm Package',
              href: 'https://www.npmjs.com/package/security-scanner-mcp',
            },
            {
              label: 'Docker Hub',
              href: 'https://hub.docker.com/r/ongjin/security-scanner-mcp',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Security Scanner MCP. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'typescript', 'javascript', 'python', 'java', 'go', 'yaml', 'docker'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
