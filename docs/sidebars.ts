import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Getting Started',
      items: ['installation', 'quick-start'],
    },
    {
      type: 'category',
      label: 'Features',
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
      items: [
        'usage/basic-usage',
        'usage/cli',
        'usage/mcp-tools',
      ],
    },
    {
      type: 'category',
      label: 'Advanced',
      items: [
        'advanced/external-tools',
        'advanced/reporting',
        'advanced/integration',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'reference/vulnerabilities',
        'reference/configuration',
        'reference/api',
      ],
    },
  ],
};

export default sidebars;
