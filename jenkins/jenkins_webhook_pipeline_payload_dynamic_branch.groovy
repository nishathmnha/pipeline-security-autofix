pipeline {
  agent any

  environment {
    REPO_URL = 'https://github.com/nishathmnha/demo-local-jenkins-pipeline.git'
    REPO_NAME = 'nishathmnha/demo-local-jenkins-pipeline'
    APP_REPO_NAME = 'nishathmnha/demo-springboot-vuln-service'
    SOURCE_BRANCH = 'main'

    APP_DIR = 'jenkins-webhook-and-github-setup/demo-springboot-vuln-service'
    IMAGE_NAME = 'local/demo-springboot-vuln-service'
    CONTAINER_NAME = 'demo-springboot-vuln-service'
    HOST_PORT = '8082'
    HEALTHCHECK_PATH = '/health'
    RUN_SMOKE_TEST = 'false'
    DOCKER_BIN = 'docker'
    TRIVY_BIN = 'trivy'
    TRIVY_CACHE_DIR = '/var/jenkins_home/trivy-cache'

    VULN_REPORT_SEVERITY = 'HIGH,CRITICAL'
    VULN_GATE_SEVERITY = 'CRITICAL'

    WEBHOOK_URL = 'http://host.docker.internal:8000/api/v1/webhooks/jenkins/failure'
    WEBHOOK_SECRET = 'change-me'
    LOCAL_REPO_PATH = 'D:/DIALOG/DESKTOP/AI -Products/Project 07 - Automated vulnerability detection and remediation for CICD pipelines/jenkins-webhook-and-github-setup/demo-springboot-vuln-service'
    LOG_DIR = 'pipeline-logs'
  }

  stages {
    stage('Checkout From GitHub') {
      steps {
        deleteDir()
        checkout([
          $class: 'GitSCM',
          branches: [[name: "*/${SOURCE_BRANCH}"]],
          userRemoteConfigs: [[url: "${REPO_URL}"]]
        ])
        sh '''#!/bin/bash
          set -euo pipefail
          mkdir -p "${LOG_DIR}"
          test -f "${APP_DIR}/pom.xml"
          test -f "${APP_DIR}/Dockerfile"
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
            -t "${IMAGE_NAME}:${BUILD_NUMBER}" \
            -t "${IMAGE_NAME}:latest" \
            "${APP_DIR}" | tee "${LOG_DIR}/build-image.log"
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
            "${APP_DIR}" | tee "${LOG_DIR}/scan-dependencies.log"

          "${TRIVY_BIN}" fs \
            --cache-dir "${TRIVY_CACHE_DIR}" \
            --scanners vuln \
            --severity "${VULN_GATE_SEVERITY}" \
            --ignore-unfixed \
            --format table \
            --no-progress \
            --timeout 30m \
            --exit-code 1 \
            "${APP_DIR}" | tee "${LOG_DIR}/scan-dependencies-gate.log"
        '''
      }
    }

    stage('Deploy Container') {
      steps {
        sh '''#!/bin/bash
          set -euo pipefail
          "${DOCKER_BIN}" rm -f "${CONTAINER_NAME}" || true
          "${DOCKER_BIN}" run -d \
            --name "${CONTAINER_NAME}" \
            -p "${HOST_PORT}:8080" \
            "${IMAGE_NAME}:${BUILD_NUMBER}" | tee "${LOG_DIR}/deploy-container.log"
        '''
      }
    }

    stage('Verify Deployment') {
      when {
        expression { env.RUN_SMOKE_TEST?.toBoolean() }
      }
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
        def dependencyFilePaths = [
          "${env.APP_DIR}/pom.xml"
        ]
        def dockerFilePaths = [
          "${env.APP_DIR}/Dockerfile"
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

        def resolvedBranch = env.CHANGE_BRANCH ?: env.BRANCH_NAME ?: env.GIT_BRANCH ?: env.SOURCE_BRANCH
        if (resolvedBranch?.startsWith('origin/')) {
          resolvedBranch = resolvedBranch.replaceFirst('^origin/', '')
        }
        if (resolvedBranch?.contains('/')) {
          resolvedBranch = resolvedBranch.tokenize('/').last()
        }

        def resolvedTargetBranch = env.CHANGE_TARGET ?: env.SOURCE_BRANCH ?: 'main'

        def payload = [
          job_name             : env.JOB_NAME,
          build_number         : env.BUILD_NUMBER as Integer,
          build_url            : env.BUILD_URL,
          repo                 : env.APP_REPO_NAME,
          branch               : resolvedBranch,
          target_branch        : resolvedTargetBranch,
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
