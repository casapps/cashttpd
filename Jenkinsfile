pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        timestamps()
    }

    environment {
        RUST_IMAGE = 'casjaysdev/rust:latest'
    }

    stages {
        stage('Build') {
            parallel {
                stage('Lint') {
                    agent {
                        docker { image "${RUST_IMAGE}"; reuseNode true }
                    }
                    steps {
                        sh 'cargo fmt --all --check'
                        sh 'cargo clippy --workspace --all-targets --all-features -- -D warnings'
                    }
                }
                stage('Compile') {
                    agent {
                        docker { image "${RUST_IMAGE}"; reuseNode true }
                    }
                    steps {
                        sh 'cargo build --release'
                    }
                }
            }
        }

        stage('Test') {
            parallel {
                stage('Unit Tests') {
                    agent {
                        docker { image "${RUST_IMAGE}"; reuseNode true }
                    }
                    steps {
                        sh 'cargo test --workspace --all-features'
                    }
                }
                stage('Coverage') {
                    agent {
                        docker { image "${RUST_IMAGE}"; reuseNode true }
                    }
                    steps {
                        // IDEA.md does not declare a coverage threshold, so the
                        // PART 8 default of 60% applies.
                        sh 'cargo tarpaulin --workspace --all-features --fail-under 60'
                    }
                }
                stage('Docs') {
                    agent {
                        docker { image "${RUST_IMAGE}"; reuseNode true }
                    }
                    steps {
                        sh 'cargo doc --workspace --no-deps'
                    }
                }
                stage('License Compliance') {
                    agent {
                        docker { image "${RUST_IMAGE}"; reuseNode true }
                    }
                    steps {
                        sh 'cargo deny check licenses advisories bans sources'
                        // `cargo-about` is not part of casjaysdev/rust:latest
                        // (verified directly against the image), so this
                        // builds the local extension image
                        // (docker/Dockerfile.build) to run the
                        // attribution-drift check.
                        sh 'docker build -f docker/Dockerfile.build -t cashttpd-toolchain:ci .'
                        sh 'docker run --rm -v "$PWD":/work -w /work cashttpd-toolchain:ci cargo about generate about.hbs > LICENSE.generated.md'
                        sh "sed -n '/<!-- GENERATED:/,\$p' LICENSE.md > LICENSE.committed-generated.md"
                        sh 'diff LICENSE.committed-generated.md LICENSE.generated.md'
                    }
                }
            }
        }

        stage('Security') {
            parallel {
                stage('Secret Scan') {
                    steps {
                        script {
                            docker.image('trufflesecurity/trufflehog:latest').inside('--entrypoint=""') {
                                sh 'trufflehog git file://. --since-commit "$GIT_PREVIOUS_COMMIT" --to-commit "$GIT_COMMIT" --only-verified --fail'
                            }
                        }
                    }
                }
                stage('Workflow Policy') {
                    steps {
                        sh '''
                            set -eo pipefail
                            bad=$(grep -RhnE '^\\s*uses:\\s*[^@]+@(v?[0-9]|main|master)' .github/ .gitea/ .forgejo/ 2>/dev/null || true)
                            if [ -n "$bad" ]; then
                              echo "Unpinned actions found (must be 40-char SHAs):"
                              echo "$bad"
                              exit 1
                            fi
                        '''
                    }
                }
                stage('Vuln Scan') {
                    when {
                        expression { fileExists('Cargo.lock') }
                    }
                    steps {
                        script {
                            docker.image(env.RUST_IMAGE).inside {
                                sh 'cargo audit'
                            }
                        }
                    }
                }
                stage('Image Scan') {
                    when {
                        expression { fileExists('docker/Dockerfile') }
                    }
                    steps {
                        sh 'docker build -f docker/Dockerfile -t cashttpd-scan:${BUILD_NUMBER} .'
                        script {
                            docker.image('aquasec/trivy:0.70.0').inside('--entrypoint="" -v /var/run/docker.sock:/var/run/docker.sock') {
                                sh 'trivy image --severity CRITICAL,HIGH --exit-code 1 cashttpd-scan:${BUILD_NUMBER}'
                            }
                        }
                    }
                }
            }
        }

        stage('Release') {
            when {
                tag 'v*'
            }
            stages {
                stage('Build Targets') {
                    matrix {
                        axes {
                            axis {
                                name 'TARGET'
                                values 'x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl', \
                                       'x86_64-pc-windows-gnu', 'aarch64-pc-windows-gnullvm', \
                                       'x86_64-apple-darwin', 'aarch64-apple-darwin'
                            }
                        }
                        stages {
                            stage('Package') {
                                agent {
                                    docker { image "${RUST_IMAGE}"; reuseNode true }
                                }
                                steps {
                                    sh 'cargo build --release --target ${TARGET}'
                                    sh '''
                                        set -euo pipefail
                                        mkdir -p binaries
                                        case "$TARGET" in
                                          x86_64-unknown-linux-musl)  ARTIFACT="cashttpd-linux-amd64" ;;
                                          aarch64-unknown-linux-musl) ARTIFACT="cashttpd-linux-arm64" ;;
                                          x86_64-pc-windows-gnu)      ARTIFACT="cashttpd-windows-amd64.exe" ;;
                                          aarch64-pc-windows-gnullvm) ARTIFACT="cashttpd-windows-arm64.exe" ;;
                                          x86_64-apple-darwin)        ARTIFACT="cashttpd-darwin-amd64" ;;
                                          aarch64-apple-darwin)       ARTIFACT="cashttpd-darwin-arm64" ;;
                                        esac
                                        case "$TARGET" in
                                          *-pc-windows-*) BIN="cashttpd.exe" ;;
                                          *)              BIN="cashttpd" ;;
                                        esac
                                        cp "target/$TARGET/release/$BIN" "binaries/$ARTIFACT"
                                        sha256sum "binaries/$ARTIFACT" > "binaries/$ARTIFACT.sha256"
                                    '''
                                    archiveArtifacts artifacts: 'binaries/*', fingerprint: true
                                }
                            }
                        }
                    }
                }
                stage('SBOM and Publish') {
                    agent {
                        docker { image "${RUST_IMAGE}"; reuseNode true }
                    }
                    steps {
                        sh 'docker build -f docker/Dockerfile.build -t cashttpd-toolchain:release .'
                        sh 'docker run --rm -v "$PWD":/work -w /work cashttpd-toolchain:release cargo cyclonedx --format json'
                        sh 'cp bom.json binaries/cashttpd-bom.json'
                        archiveArtifacts artifacts: 'binaries/cashttpd-bom.json', fingerprint: true
                    }
                }
            }
        }
    }
}
