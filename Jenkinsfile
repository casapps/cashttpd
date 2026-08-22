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
                        // PART 8 default of 60% applies. Using `cargo llvm-cov`
                        // rather than `cargo tarpaulin` — both are pre-installed
                        // and AI.md PART 8 permits either, but tarpaulin's
                        // ptrace-based instrumentation needs `personality()` to
                        // disable ASLR, which fails with EPERM inside a
                        // containerized CI job (confirmed on GitHub Actions;
                        // llvm-cov avoids the risk entirely, kept consistent here).
                        sh 'cargo llvm-cov --workspace --all-features --fail-under-lines 60'
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
                        // This step runs inside the RUST_IMAGE docker agent (see
                        // this stage's `agent` block above), which already
                        // overrides the container ENTRYPOINT via Jenkins'
                        // docker-pipeline plugin, so no explicit `--entrypoint`
                        // override is needed here (unlike the ad hoc `docker run`
                        // calls below, which run outside any `agent { docker }`
                        // context and DO need the override).
                        sh 'cargo deny check licenses advisories bans sources'
                        // `cargo-about` is part of casjaysdev/rust:latest
                        // (verified directly against the image:
                        // /usr/local/bin/cargo-about is present), so this runs
                        // straight against the maintained toolchain image - no
                        // local extension image needed (AI.md "Toolchain
                        // Image": never create docker/Dockerfile.build for
                        // Rust).
                        // casjaysdev/rust:latest ships a default ENTRYPOINT (an
                        // unrelated SMTP-config script) that silently intercepts
                        // ad hoc `docker run` invocations unless overridden —
                        // confirmed via a real GitHub Actions CI run.
                        sh 'docker run --rm --entrypoint sh -v "$PWD":/work -w /work casjaysdev/rust:latest -c "cargo about generate about.hbs" > LICENSE.generated.md'
                        sh "sed -n '/<!-- GENERATED:/,\$p' LICENSE.md > LICENSE.committed-generated.md"
                        // Some upstream crates (e.g. mime_guess) ship an embedded
                        // LICENSE file with CRLF line endings, which cargo-about
                        // copies verbatim, while `.gitattributes`' `* text=auto`
                        // normalizes them to LF on commit. Strip \r from both sides
                        // (via temp files, not process substitution — Jenkins' `sh`
                        // step runs `/bin/sh`, not bash) so normalization isn't
                        // reported as drift.
                        sh 'tr -d "\\r" < LICENSE.committed-generated.md > LICENSE.committed-generated.lf.md'
                        sh 'tr -d "\\r" < LICENSE.generated.md > LICENSE.generated.lf.md'
                        sh 'diff LICENSE.committed-generated.lf.md LICENSE.generated.lf.md'
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
                        // `@(v?[0-9]|main|master)` also matches a real 40-char SHA
                        // that happens to start with a decimal digit, producing
                        // false positives — confirmed via a real CI run. Extract
                        // each `uses:` ref and reject only refs that are NOT a
                        // full 40-char hex SHA.
                        sh '''
                            set -eo pipefail
                            bad=$(grep -RhnoE '^\\s*uses:\\s*[^@]+@[^[:space:]]+' .github/ .gitea/ .forgejo/ 2>/dev/null | grep -vE '@[0-9a-fA-F]{40}$' || true)
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
                        sh 'DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile -t cashttpd-scan:${BUILD_NUMBER} .'
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
                                    // Single captured time source (AI.md PART 6 "Build
                                    // Metadata") — BUILD_EPOCH is captured once per stage
                                    // and, with COMMIT_ID, exported for build.rs to embed
                                    // via APP_BUILD_EPOCH/APP_COMMIT_ID.
                                    sh '''
                                        set -euo pipefail
                                        BUILD_EPOCH="$(date -u +%s)"
                                        export BUILD_EPOCH
                                        export COMMIT_ID="${GIT_COMMIT}"
                                        cargo build --release --target ${TARGET}
                                    '''
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
                                        case "$TARGET" in
                                          *-unknown-linux-musl)
                                            # musl static-pie binaries self-reference their own
                                            # musl loader stub in `ldd` output even though they
                                            # have no external dynamic dependency — `file` is the
                                            # authoritative static-linkage check.
                                            ldd "target/$TARGET/release/cashttpd" 2>&1 || true
                                            file "target/$TARGET/release/cashttpd" | grep -qE 'static-pie linked|statically linked'
                                            ;;
                                          *-apple-darwin)
                                            otool -L "target/$TARGET/release/cashttpd"
                                            ;;
                                          *-pc-windows-*)
                                            dumpbin /dependents "target/$TARGET/release/cashttpd.exe"
                                            ;;
                                        esac
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
                        // `cargo-cyclonedx` is part of casjaysdev/rust:latest
                        // (verified directly against the image:
                        // /usr/local/bin/cargo-cyclonedx is present) - no local
                        // extension image needed (AI.md "Toolchain Image":
                        // never create docker/Dockerfile.build for Rust). Same
                        // default-ENTRYPOINT interception issue as the License
                        // Compliance stage above — see its comment.
                        sh 'docker run --rm --entrypoint sh -v "$PWD":/work -w /work casjaysdev/rust:latest -c "cargo cyclonedx --format json"'
                        sh 'cp bom.json binaries/cashttpd-bom.json'
                        // Two aggregate checksum files covering every published
                        // artifact (AI.md PART 2 "Binary Model" / PART 5 "Release
                        // Artifacts") — never per-artifact sidecar files.
                        sh '''
                            set -euo pipefail
                            cd binaries
                            sha256sum * > sha256.txt
                            sha512sum * > sha512.txt
                        '''
                        archiveArtifacts artifacts: 'binaries/cashttpd-bom.json,binaries/sha256.txt,binaries/sha512.txt', fingerprint: true
                    }
                }
                stage('Publish Image') {
                    steps {
                        // Requires a Jenkins username/password credential with id
                        // `container-registry` holding a token for the registry
                        // derived from GIT_URL (see docker/README.md).
                        withCredentials([usernamePassword(credentialsId: 'container-registry',
                                                          usernameVariable: 'REGISTRY_USER',
                                                          passwordVariable: 'REGISTRY_TOKEN')]) {
                            // No hardcoded org, project name, or registry value
                            // (AI.md PART 5 "Portability Rule") — org/name/host are
                            // parsed from GIT_URL so a fork keeps working. All image
                            // metadata is applied as OCI annotations on the manifest
                            // index, never as LABEL blocks (AI.md PART 5 "OCI
                            // Annotations (No LABEL Policy)").
                            sh '''
                                set -eu
                                url="${GIT_URL%.git}"
                                host="$(printf '%s' "$url" | sed -E 's#^[a-z]+://##; s#^[^@]*@##; s#[:/].*$##')"
                                path="$(printf '%s' "$url" | sed -E 's#^[a-z]+://[^/]+/##; s#^[^:]+:##')"
                                org="$(printf '%s' "${path%/*}" | tr '[:upper:]' '[:lower:]')"
                                name="$(printf '%s' "${path##*/}" | tr '[:upper:]' '[:lower:]')"
                                case "$host" in
                                  github.com) registry="ghcr.io" ;;
                                  *)          registry="$host" ;;
                                esac
                                image="$registry/$org/$name"

                                if [ -s release.txt ]; then
                                  VERSION="$(tr -d '[:space:]' < release.txt)"
                                else
                                  VERSION="${TAG_NAME:-0.0.0}"
                                fi

                                BUILD_EPOCH="$(date -u +%s)"
                                BUILD_DATE="$(date -u -d "@$BUILD_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"

                                printf '%s' "$REGISTRY_TOKEN" | docker login -u "$REGISTRY_USER" --password-stdin "$registry"
                                docker run --rm --privileged tonistiigi/binfmt:latest --install all
                                docker buildx create --use --name "$name-builder" 2>/dev/null || true

                                set -- \
                                  --annotation "index,manifest:maintainer=$org <$org@casjay.pro>" \
                                  --annotation "index,manifest:org.opencontainers.image.vendor=$org" \
                                  --annotation "index,manifest:org.opencontainers.image.authors=$org" \
                                  --annotation "index,manifest:org.opencontainers.image.title=$name" \
                                  --annotation "index,manifest:org.opencontainers.image.base.name=$name" \
                                  --annotation "index,manifest:org.opencontainers.image.description=Containerized version of $name" \
                                  --annotation "index,manifest:org.opencontainers.image.url=$url" \
                                  --annotation "index,manifest:org.opencontainers.image.source=$url" \
                                  --annotation "index,manifest:org.opencontainers.image.documentation=$url" \
                                  --annotation "index,manifest:org.opencontainers.image.vcs-type=Git" \
                                  --annotation "index,manifest:org.opencontainers.image.licenses=MIT" \
                                  --annotation "index,manifest:org.opencontainers.image.created=$BUILD_DATE" \
                                  --annotation "index,manifest:org.opencontainers.image.version=$VERSION" \
                                  --annotation "index,manifest:org.opencontainers.image.schema-version=$VERSION" \
                                  --annotation "index,manifest:org.opencontainers.image.revision=$GIT_COMMIT" \
                                  --annotation "index,manifest:com.github.containers.toolbox=false"

                                docker buildx build --push \
                                  -f docker/Dockerfile \
                                  --platform linux/amd64,linux/arm64 \
                                  --provenance=false \
                                  --build-arg "BUILD_EPOCH=$BUILD_EPOCH" \
                                  --build-arg "COMMIT_ID=$GIT_COMMIT" \
                                  --build-arg "PROJECT_ORG=$org" \
                                  --build-arg "PROJECT_NAME=$name" \
                                  "$@" \
                                  -t "$image:latest" \
                                  -t "$image:$VERSION" \
                                  .
                            '''
                        }
                    }
                }
            }
        }
    }
}
