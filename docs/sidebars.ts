import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Getting Started',
      link: {
        type: 'generated-index',
        description: 'Get started with Security Scanner MCP in minutes.',
      },
      items: ['installation', 'quick-start'],
    },
    {
      type: 'category',
      label: 'Features',
      link: {
        type: 'generated-index',
        description: 'Explore all the powerful features of Security Scanner MCP.',
      },
      items: [
        'features/code-scanning',
        'features/iac-scanning',
        'features/auto-fix',
        'features/sandbox',
      ],
    },
    {
      type: 'category',
      label: 'Usage',
      link: {
        type: 'generated-index',
        description: 'Learn how to use Security Scanner MCP in various scenarios.',
      },
      items: [
        'usage/basic-usage',
        'usage/cli',
        'usage/mcp-tools',
      ],
    },
    {
      type: 'category',
      label: 'Advanced',
      link: {
        type: 'generated-index',
        description: 'Advanced features and integration options.',
      },
      items: [
        'advanced/external-tools',
        'advanced/reporting',
        'advanced/integration',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      link: {
        type: 'generated-index',
        description: 'Complete API and configuration reference.',
      },
      items: [
        'reference/vulnerabilities',
        'reference/configuration',
        'reference/api',
      ],
    },
  ],
};

export default sidebars;
