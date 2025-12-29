# Security Scanner MCP - Unified Dockerfile
# 소스 빌드와 npm 패키지 빌드 모두 지원하는 통합 Dockerfile
#
# 사용법:
#   소스 빌드:     docker build -t security-scanner-mcp:latest .
#                  docker build --target source -t security-scanner-mcp:latest .
#
#   npm 패키지:    docker build --target npm -t security-scanner-mcp:latest .

# =============================================================================
# Stage 1: Source Builder
# =============================================================================
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

RUN npm ci --production=false

COPY src ./src
RUN npm run build

# =============================================================================
# Stage 2: Base Runtime (공통 환경 설정)
# =============================================================================
FROM node:20-alpine AS base

# 외부 보안 도구 버전
ENV TRIVY_VERSION=0.50.4 \
    GITLEAKS_VERSION=8.18.4

# 시스템 패키지 및 보안 도구 설치
RUN apk add --no-cache \
    python3 \
    py3-pip \
    wget \
    curl \
    git \
    ca-certificates && \
    # Trivy 설치
    wget -qO- https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz | \
    tar xz -C /usr/local/bin && \
    # GitLeaks 설치
    wget -qO- https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz | \
    tar xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/gitleaks && \
    # Checkov 설치 (Python)
    pip3 install --no-cache-dir --break-system-packages checkov && \
    # 버전 확인
    trivy --version && \
    gitleaks version && \
    checkov --version

# 보안 강화: 비root 사용자 생성
RUN addgroup -g 1001 scanner && \
    adduser -D -u 1001 -G scanner scanner

# 분석 대상 코드 마운트 디렉토리 생성
RUN mkdir -p /target && \
    chown scanner:scanner /target

WORKDIR /app

# 환경 변수
ENV NODE_ENV=production

# =============================================================================
# Stage 3: Source Build (소스 코드에서 빌드) - 기본 타겟
# =============================================================================
FROM base AS source

# 프로덕션 의존성 설치
COPY package*.json ./
RUN npm ci --production && \
    npm cache clean --force

# builder에서 빌드된 파일 복사
COPY --from=builder --chown=scanner:scanner /app/dist ./dist

# 권한 설정
RUN chown -R scanner:scanner /app

# 비root 사용자로 전환
USER scanner

# Entrypoint
CMD ["node", "dist/sandbox/scanner-entrypoint.js"]

# =============================================================================
# Stage 4: NPM Package Build (npm으로 설치된 패키지)
# =============================================================================
FROM base AS npm

# npm 패키지의 파일들 복사
COPY --chown=scanner:scanner package*.json ./
COPY --chown=scanner:scanner dist ./dist
COPY --chown=scanner:scanner node_modules ./node_modules

# 권한 설정
RUN chown -R scanner:scanner /app

# 비root 사용자로 전환
USER scanner

# Entrypoint
CMD ["node", "dist/sandbox/scanner-entrypoint.js"]
