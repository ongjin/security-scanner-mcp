/**
 * Docker 샌드박스 실행 매니저
 *
 * Docker 컨테이너를 사용하여 격리된 환경에서 보안 스캔을 실행합니다.
 * 리소스 제한, 타임아웃, 네트워크 격리 등을 적용합니다.
 *
 * @author zerry
 */

import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import * as crypto from 'crypto';

const execAsync = promisify(exec);

/**
 * Docker 실행 옵션
 */
export interface DockerRunOptions {
    /** 이미지 이름 */
    image: string;

    /** 실행할 명령어 */
    command: string[];

    /** 환경 변수 */
    env?: Record<string, string>;

    /** CPU 제한 (코어 수) */
    cpuLimit?: number;

    /** 메모리 제한 (MB) */
    memoryLimit?: number;

    /** 타임아웃 (ms) */
    timeout?: number;

    /** 네트워크 비활성화 */
    noNetwork?: boolean;

    /** 읽기 전용 루트 파일시스템 */
    readonlyRootfs?: boolean;

    /** 볼륨 마운트 */
    volumes?: Array<{
        host: string;
        container: string;
        readonly?: boolean;
    }>;
}

/**
 * Docker 실행 결과
 */
export interface DockerRunResult {
    success: boolean;
    stdout: string;
    stderr: string;
    exitCode: number;
    timedOut: boolean;
    error?: string;
}

/**
 * Docker 샌드박스 매니저
 */
export class DockerSandboxManager {
    private static readonly DEFAULT_IMAGE = 'security-scanner-mcp:latest';
    private static readonly DEFAULT_TIMEOUT = 30000; // 30초
    private static readonly DEFAULT_MEMORY_LIMIT = 512; // 512MB
    private static readonly DEFAULT_CPU_LIMIT = 0.5; // 0.5 코어

    /**
     * Docker가 설치되어 있는지 확인
     */
    async isDockerAvailable(): Promise<boolean> {
        try {
            await execAsync('docker --version');
            return true;
        } catch {
            return false;
        }
    }

    /**
     * 이미지가 존재하는지 확인
     */
    async imageExists(imageName: string): Promise<boolean> {
        try {
            const { stdout } = await execAsync(`docker images -q ${imageName}`);
            return stdout.trim().length > 0;
        } catch {
            return false;
        }
    }

    /**
     * 이미지 빌드
     */
    async buildImage(
        dockerfilePath: string = '.',
        imageName: string = DockerSandboxManager.DEFAULT_IMAGE
    ): Promise<void> {
        const command = `docker build -t ${imageName} ${dockerfilePath}`;
        await execAsync(command, { maxBuffer: 10 * 1024 * 1024 }); // 10MB buffer
    }

    /**
     * 컨테이너 실행
     */
    async run(options: DockerRunOptions): Promise<DockerRunResult> {
        const containerName = this.generateContainerName();

        try {
            // Docker 명령어 구성
            const dockerArgs = this.buildDockerArgs(options, containerName);

            // 타임아웃 설정
            const timeout = options.timeout || DockerSandboxManager.DEFAULT_TIMEOUT;

            // 컨테이너 실행
            const result = await this.executeContainer(dockerArgs, timeout);

            // 컨테이너 정리
            await this.cleanup(containerName);

            return result;
        } catch (error) {
            // 에러 발생 시에도 컨테이너 정리
            await this.cleanup(containerName);

            return {
                success: false,
                stdout: '',
                stderr: error instanceof Error ? error.message : String(error),
                exitCode: -1,
                timedOut: false,
                error: error instanceof Error ? error.message : String(error),
            };
        }
    }

    /**
     * Docker 인자 구성
     */
    private buildDockerArgs(options: DockerRunOptions, containerName: string): string[] {
        const args: string[] = [
            'run',
            '--rm',
            '--name', containerName,
        ];

        // 리소스 제한
        const memoryLimit = options.memoryLimit || DockerSandboxManager.DEFAULT_MEMORY_LIMIT;
        const cpuLimit = options.cpuLimit || DockerSandboxManager.DEFAULT_CPU_LIMIT;

        args.push('--memory', `${memoryLimit}m`);
        args.push('--cpus', String(cpuLimit));

        // 네트워크 제한
        if (options.noNetwork !== false) {
            args.push('--network', 'none');
        }

        // 읽기 전용 루트 파일시스템
        if (options.readonlyRootfs !== false) {
            args.push('--read-only');
        }

        // 보안 옵션
        args.push('--security-opt', 'no-new-privileges');
        args.push('--cap-drop', 'ALL');

        // 환경 변수
        if (options.env) {
            for (const [key, value] of Object.entries(options.env)) {
                args.push('-e', `${key}=${value}`);
            }
        }

        // 볼륨 마운트
        if (options.volumes) {
            for (const volume of options.volumes) {
                const mode = volume.readonly ? 'ro' : 'rw';
                args.push('-v', `${volume.host}:${volume.container}:${mode}`);
            }
        }

        // 이미지와 명령어
        args.push(options.image);
        args.push(...options.command);

        return args;
    }

    /**
     * 컨테이너 실행
     */
    private executeContainer(args: string[], timeout: number): Promise<DockerRunResult> {
        return new Promise((resolve) => {
            let stdout = '';
            let stderr = '';
            let timedOut = false;

            const proc = spawn('docker', args);

            // 타임아웃 타이머
            const timeoutId = setTimeout(() => {
                timedOut = true;
                proc.kill('SIGKILL');
            }, timeout);

            // stdout 수집
            proc.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            // stderr 수집
            proc.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            // 프로세스 종료
            proc.on('close', (code) => {
                clearTimeout(timeoutId);

                resolve({
                    success: !timedOut && code === 0,
                    stdout,
                    stderr,
                    exitCode: code || -1,
                    timedOut,
                });
            });

            // 에러 처리
            proc.on('error', (error) => {
                clearTimeout(timeoutId);

                resolve({
                    success: false,
                    stdout,
                    stderr,
                    exitCode: -1,
                    timedOut,
                    error: error.message,
                });
            });
        });
    }

    /**
     * 컨테이너 정리
     */
    private async cleanup(containerName: string): Promise<void> {
        try {
            // 실행 중인 컨테이너 강제 종료
            await execAsync(`docker rm -f ${containerName}`);
        } catch {
            // 이미 삭제되었거나 존재하지 않으면 무시
        }
    }

    /**
     * 컨테이너 이름 생성
     */
    private generateContainerName(): string {
        const timestamp = Date.now();
        const random = crypto.randomBytes(4).toString('hex');
        return `scanner-${timestamp}-${random}`;
    }

    /**
     * 모든 스캐너 컨테이너 정리
     */
    async cleanupAllScannerContainers(): Promise<void> {
        try {
            const { stdout } = await execAsync('docker ps -a --filter "name=scanner-" -q');
            const containerIds = stdout.trim().split('\n').filter(id => id.length > 0);

            if (containerIds.length > 0) {
                await execAsync(`docker rm -f ${containerIds.join(' ')}`);
            }
        } catch {
            // 에러 무시
        }
    }
}

/**
 * 싱글톤 인스턴스
 */
export const dockerSandboxManager = new DockerSandboxManager();
