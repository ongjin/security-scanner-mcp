---
sidebar_position: 3
---

# CI/CD Integration

Integrate Security Scanner MCP into your development workflow.

## GitHub Actions

### Basic Workflow

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Pull Security Scanner
        run: docker pull ongjin/security-scanner-mcp:latest
      
      - name: Scan Code
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/code:ro \
            ongjin/security-scanner-mcp:latest \
            scan /code
```

### Advanced Workflow with SARIF

```yaml
name: Advanced Security Scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan with SARIF
        run: |
          docker run --rm \
            -v $(pwd):/code:ro \
            ongjin/security-scanner-mcp:latest \
            scan /code --format sarif > security.sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security.sarif
          category: security-scanner-mcp
```

## GitLab CI

```yaml
security-scan:
  image: docker:latest
  services:
    - docker:dind
  
  before_script:
    - docker pull ongjin/security-scanner-mcp:latest
  
  script:
    - docker run --rm -v $(pwd):/code:ro 
        ongjin/security-scanner-mcp:latest scan /code
  
  artifacts:
    reports:
      sast: security-report.json
  
  only:
    - merge_requests
    - main
```

## Jenkins

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    docker.image('ongjin/security-scanner-mcp:latest')
                          .inside('-v $WORKSPACE:/code:ro') {
                        sh 'scan /code --format json > security-report.json'
                    }
                }
            }
        }
        
        stage('Publish Results') {
            steps {
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'security-report.html',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

## CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: docker:latest
    
    steps:
      - checkout
      - setup_remote_docker
      
      - run:
          name: Pull Scanner
          command: docker pull ongjin/security-scanner-mcp:latest
      
      - run:
          name: Run Scan
          command: |
            docker run --rm \
              -v $(pwd):/code:ro \
              ongjin/security-scanner-mcp:latest \
              scan /code
      
      - store_artifacts:
          path: security-report.json

workflows:
  version: 2
  security:
    jobs:
      - security-scan
```

## Pre-commit Hooks

### Using Husky

```bash
# Install
npm install --save-dev husky

# Setup
npx husky install
npx husky add .husky/pre-commit "npm run security-scan"
```

```json
{
  "scripts": {
    "security-scan": "security-scanner-mcp scan src/"
  }
}
```

### Using pre-commit Framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: security-scan
        name: Security Scanner MCP
        entry: docker run --rm -v $(pwd):/code:ro ongjin/security-scanner-mcp:latest scan
        language: system
        pass_filenames: false
```

## IDE Integration

### VS Code

Create task (`.vscode/tasks.json`):

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Security Scan",
      "type": "shell",
      "command": "docker",
      "args": [
        "run", "--rm",
        "-v", "${workspaceFolder}:/code:ro",
        "ongjin/security-scanner-mcp:latest",
        "scan", "/code/${relativeFile}"
      ],
      "presentation": {
        "reveal": "always",
        "panel": "new"
      },
      "problemMatcher": []
    }
  ]
}
```

### IntelliJ IDEA

Create External Tool:
1. Settings → Tools → External Tools
2. Add new tool:
   - Name: Security Scanner
   - Program: docker
   - Arguments: `run --rm -v $ProjectFileDir$:/code:ro ongjin/security-scanner-mcp:latest scan /code/$FilePath$`

## Deployment Gates

### Block on Critical Issues

```yaml
- name: Security Gate
  run: |
    docker run --rm \
      -v $(pwd):/code:ro \
      ongjin/security-scanner-mcp:latest \
      scan /code --fail-on critical
    
    if [ $? -ne 0 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

### Severity Thresholds

```bash
# Fail on high or critical
scan --min-severity high

# Fail on any vulnerability
scan --min-severity low
```

## Notification Integration

### Slack

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Security scan failed!",
        "attachments": [{
          "color": "danger",
          "fields": [{
            "title": "Repository",
            "value": "${{ github.repository }}"
          }]
        }]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### Email

```yaml
- name: Send Email
  if: failure()
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: smtp.gmail.com
    server_port: 465
    username: ${{secrets.MAIL_USERNAME}}
    password: ${{secrets.MAIL_PASSWORD}}
    subject: Security Scan Failed
    body: Check the workflow run for details
```

## Metrics and Tracking

### Prometheus

```yaml
- name: Export Metrics
  run: |
    cat <<EOF > metrics.txt
    # HELP security_vulnerabilities Total vulnerabilities found
    # TYPE security_vulnerabilities gauge
    security_vulnerabilities{severity="critical"} $(jq '.summary.critical' report.json)
    security_vulnerabilities{severity="high"} $(jq '.summary.high' report.json)
    EOF
```

### Grafana Dashboard

Track over time:
- Vulnerability trends
- Time to fix
- Severity distribution
- Category breakdown

## Best Practices

1. **Run on every commit**: Catch issues early
2. **Block merges**: Require clean scans
3. **Set thresholds**: Define acceptable risk levels
4. **Track metrics**: Monitor improvement
5. **Automate fixes**: Use auto-remediation where possible
6. **Regular updates**: Keep scanner and rules current

## Troubleshooting

### Docker Permission Issues

```bash
# Add user to docker group
sudo usermod -aG docker $USER
```

### CI/CD Timeout

```yaml
# Increase timeout
timeout-minutes: 30
```

### Large Codebases

```bash
# Scan incrementally
git diff --name-only HEAD~1 | xargs security-scanner-mcp scan
```

## Next Steps

- [Reporting](./reporting.md) - Generate comprehensive reports
- [External Tools](./external-tools.md) - Enhanced scanning
- [Configuration](../reference/configuration.md) - Advanced settings
