import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

import styles from './index.module.css';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/intro">
            Get Started →
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home(): JSX.Element {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title}`}
      description="MCP server that scans AI-generated code for security vulnerabilities">
      <HomepageHeader />
      <main>
        <section className={styles.features}>
          <div className="container">
            <div className="row">
              <div className={clsx('col col--4')}>
                <div className="text--center padding-horiz--md">
                  <Heading as="h3">🎯 Code Security Scanning</Heading>
                  <p>
                    Detect hardcoded secrets, SQL/NoSQL injection, XSS, crypto weaknesses,
                    and authentication vulnerabilities in your code.
                  </p>
                </div>
              </div>
              <div className={clsx('col col--4')}>
                <div className="text--center padding-horiz--md">
                  <Heading as="h3">🏗️ IaC Security</Heading>
                  <p>
                    Scan Dockerfile, Kubernetes, and Terraform configurations for
                    security misconfigurations with industry-standard tools.
                  </p>
                </div>
              </div>
              <div className={clsx('col col--4')}>
                <div className="text--center padding-horiz--md">
                  <Heading as="h3">🛠️ Auto-Fix & Reports</Heading>
                  <p>
                    Get AI-generated fix suggestions and comprehensive reports with
                    Mermaid diagrams and SARIF format.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
