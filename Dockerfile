# Security Scanner MCP - Sandbox Dockerfile
# 보안 스캐너를 안전한 샌드박스 환경에서 실행하기 위한 컨테이너

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# 의존성 파일 복사
COPY package*.json ./
COPY tsconfig.json ./

# 의존성 설치
RUN npm ci --production=false

# 소스 코드 복사
COPY src ./src

# 빌드
RUN npm run build

# Stage 2: Runtime
FROM node:20-alpine

# 보안 강화
RUN addgroup -g 1001 scanner && \
    adduser -D -u 1001 -G scanner scanner

WORKDIR /app

# 프로덕션 의존성만 설치
COPY package*.json ./
RUN npm ci --production && \
    npm cache clean --force

# 빌드된 파일 복사
COPY --from=builder /app/dist ./dist

# 권한 설정
RUN chown -R scanner:scanner /app

# 비root 사용자로 전환
USER scanner

# 환경 변수
ENV NODE_ENV=production

# 샌드박스 스캔 entrypoint를 기본 명령으로 설정
# 호스트에서 실행 시 코드 파일 경로를 환경변수로 전달
CMD ["node", "dist/sandbox/scanner-entrypoint.js"]
