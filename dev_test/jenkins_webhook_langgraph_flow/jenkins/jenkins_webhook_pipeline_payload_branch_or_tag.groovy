pipeline {
  agent any

  parameters {
    string(
      name: 'GIT_REPO_URL',
      defaultValue: 'https://github.com/nishathmnha/demo-springboot-vuln-service.git',
      description: 'Git repository URL to build'
    )
    choice(
      name: 'REF_TYPE',
      choices: ['branch', 'tag'],
      description: 'Choose whether to build from a branch or a tag'
    )
    string(
      name: 'REF_NAME',
      defaultValue: 'main',
      description: 'Branch name or tag name to build'
    )
  }

  environment {
    DEFAULT_BRANCH = 'main'

    HOST_PORT = '8082'
    HEALTHCHECK_PATH = '/health'
    DOCKER_BIN = 'docker'
    TRIVY_BIN = 'trivy'
    TRIVY_CACHE_DIR = '/var/jenkins_home/trivy-cache'

    VULN_REPORT_SEVERITY = 'HIGH,CRITICAL'
    VULN_GATE_SEVERITY = 'CRITICAL'

    WEBHOOK_URL = 'http://host.docker.internal:8000/api/v1/webhooks/jenkins/failure'
    WEBHOOK_SECRET = 'change-me'
    LOG_DIR = 'pipeline-logs'
  }

  stages {
    stage('Checkout From GitHub') {
      steps {
        script {
          def resolvedRefName = params.REF_NAME?.trim() ?: env.DEFAULT_BRANCH
          env.RESOLVED_REPO_URL = params.GIT_REPO_URL?.trim()
          env.RESOLVED_REPO_NAME = env.RESOLVED_REPO_URL
            .replaceFirst('^.*github.com[\\\\/:]', '')
            .replaceFirst(/\.git$/, '')
          env.RESOLVED_REPO_SLUG = env.RESOLVED_REPO_NAME.tokenize('/').last()
          env.RESOLVED_IMAGE_NAME = "local/${env.RESOLVED_REPO_SLUG}"
          env.RESOLVED_CONTAINER_NAME = env.RESOLVED_REPO_SLUG
          def checkoutRef = params.REF_TYPE == 'tag'
            ? "refs/tags/${resolvedRefName}"
            : "*/${resolvedRefName}"

          deleteDir()
          checkout([
            $class: 'GitSCM',
            branches: [[name: checkoutRef]],
            userRemoteConfigs: [[url: "${env.RESOLVED_REPO_URL}"]]
          ])

          env.RESOLVED_APP_DIR = sh(
            returnStdout: true,
            script: '''#!/bin/bash
              set -euo pipefail

              if [[ -f "pom.xml" && -f "Dockerfile" ]]; then
                printf '.'
                exit 0
              fi

              while IFS= read -r pomPath; do
                dir="$(dirname "$pomPath")"
                if [[ "$dir" == "." ]]; then
                  dir="."
                else
                  dir="${dir#./}"
                fi

                if [[ -n "$dir" && -f "$dir/Dockerfile" ]]; then
                  printf '%s' "$dir"
                  exit 0
                fi
              done < <(find . -type f -name pom.xml | sort -u)

              echo "Unable to locate an application directory containing both pom.xml and Dockerfile." >&2
              exit 1
            '''
          ).trim()
        }

        sh '''#!/bin/bash
          set -euo pipefail
          mkdir -p "${LOG_DIR}"
          test -f "${RESOLVED_APP_DIR}/pom.xml"
          test -f "${RESOLVED_APP_DIR}/Dockerfile"
        '''
      }
    }

    stage('Validate Environment') {
      steps {
        sh '''#!/bin/bash
          set -euo pipefail
          command -v "${DOCKER_BIN}"
          command -v "${TRIVY_BIN}"
        '''
      }
    }

    stage('Build Image') {
      steps {
        sh '''#!/bin/bash
          set -euo pipefail
          "${DOCKER_BIN}" build \
            -t "${RESOLVED_IMAGE_NAME}:${BUILD_NUMBER}" \
            -t "${RESOLVED_IMAGE_NAME}:latest" \
            "${RESOLVED_APP_DIR}" | tee "${LOG_DIR}/build-image.log"
        '''
      }
    }

    stage('Scan Dependencies') {
      steps {
        sh '''#!/bin/bash
          set -euo pipefail
          mkdir -p "${TRIVY_CACHE_DIR}"

          "${TRIVY_BIN}" fs \
            --cache-dir "${TRIVY_CACHE_DIR}" \
            --scanners vuln \
            --severity "${VULN_REPORT_SEVERITY}" \
            --ignore-unfixed \
            --format table \
            --no-progress \
            --timeout 30m \
            "${RESOLVED_APP_DIR}" | tee "${LOG_DIR}/scan-dependencies.log"

          "${TRIVY_BIN}" fs \
            --cache-dir "${TRIVY_CACHE_DIR}" \
            --scanners vuln \
            --severity "${VULN_GATE_SEVERITY}" \
            --ignore-unfixed \
            --format table \
            --no-progress \
            --timeout 30m \
            --exit-code 1 \
            "${RESOLVED_APP_DIR}" | tee "${LOG_DIR}/scan-dependencies-gate.log"
        '''
      }
    }

    stage('Deploy Container') {
      steps {
        sh '''#!/bin/bash
          set -euo pipefail
          "${DOCKER_BIN}" rm -f "${RESOLVED_CONTAINER_NAME}" || true
          "${DOCKER_BIN}" run -d \
            --name "${RESOLVED_CONTAINER_NAME}" \
            -p "${HOST_PORT}:8080" \
            "${RESOLVED_IMAGE_NAME}:${BUILD_NUMBER}" | tee "${LOG_DIR}/deploy-container.log"
        '''
      }
    }

    stage('Verify Deployment') {
      steps {
        sh '''#!/bin/bash
          set -euo pipefail
          sleep 8
          curl --fail --show-error "http://host.docker.internal:${HOST_PORT}${HEALTHCHECK_PATH}" | tee "${LOG_DIR}/verify-deployment.log"
        '''
      }
    }
  }

  post {
    failure {
      script {
        def resolvedRefName = params.REF_NAME?.trim() ?: env.DEFAULT_BRANCH
        def dependencyFilePaths = [
          "${env.RESOLVED_APP_DIR}/pom.xml"
        ]
        def dockerFilePaths = [
          "${env.RESOLVED_APP_DIR}/Dockerfile"
        ]

        def logFiles = [
          'build-image.log',
          'scan-dependencies.log',
          'scan-dependencies-gate.log',
          'deploy-container.log',
          'verify-deployment.log'
        ]

        def consoleSections = []
        logFiles.each { logFile ->
          def path = "${env.LOG_DIR}/${logFile}"
          if (fileExists(path)) {
            consoleSections << "===== ${logFile} =====\n${readFile(path)}"
          }
        }

        def payload = [
          job_name             : env.JOB_NAME,
          build_number         : env.BUILD_NUMBER as Integer,
          build_url            : env.BUILD_URL,
          repo                 : env.RESOLVED_REPO_NAME,
          branch               : params.REF_TYPE == 'branch' ? resolvedRefName : '',
          target_branch        : params.REF_TYPE == 'branch' ? resolvedRefName : '',
          ref_type             : params.REF_TYPE,
          ref_name             : resolvedRefName,
          status               : 'FAILED',
          console_output       : consoleSections.join('\n\n'),
          dependency_file_paths: dependencyFilePaths,
          docker_file_paths    : dockerFilePaths
        ]

        writeFile(
          file: 'webhook_payload.json',
          text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(payload))
        )

        def webhookStatus = sh(
          returnStatus: true,
          script: '''#!/bin/bash
            set -euo pipefail
            curl --fail --show-error -X POST "${WEBHOOK_URL}" \
              -H "Content-Type: application/json" \
              -H "X-Webhook-Secret: ${WEBHOOK_SECRET}" \
              --data @webhook_payload.json
          '''
        )

        if (webhookStatus != 0) {
          echo "Webhook delivery failed with exit code ${webhookStatus}. Is the FastAPI monitor running on port 8000?"
        }
      }
    }
  }
}
