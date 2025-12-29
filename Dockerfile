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

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# MCP 서버 실행
CMD ["node", "dist/index.js"]
