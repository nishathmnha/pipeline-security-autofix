pipeline {
    agent any

    environment {
        WEBHOOK_URL = 'http://host.docker.internal:8000/api/v1/webhooks/jenkins/failure'
        WEBHOOK_SECRET = credentials('jenkins-webhook-secret')
    }

    stages {
        stage('Build') {
            steps {
                sh 'echo "build stage placeholder"'
            }
        }

        stage('Scan') {
            steps {
                sh '''
                    mkdir -p reports
                    if [ -f scan-dependencies.log ]; then cp scan-dependencies.log reports/scan-dependencies.log; fi
                    if [ -f scan-dependencies-gate.log ]; then cp scan-dependencies-gate.log reports/scan-dependencies-gate.log; fi
                '''
            }
        }
    }

    post {
        failure {
            script {
                def dependencyFilePaths = [
                    'jenkins-webhook-and-github-setup/demo-springboot-vuln-service/pom.xml'
                ]
                def dockerFilePaths = [
                    'jenkins-webhook-and-github-setup/demo-springboot-vuln-service/Dockerfile'
                ]

                def consoleParts = []
                if (fileExists('reports/scan-dependencies.log')) {
                    consoleParts << '===== scan-dependencies.log ====='
                    consoleParts << readFile('reports/scan-dependencies.log')
                }
                if (fileExists('reports/scan-dependencies-gate.log')) {
                    consoleParts << '===== scan-dependencies-gate.log ====='
                    consoleParts << readFile('reports/scan-dependencies-gate.log')
                }

                if (consoleParts.isEmpty()) {
                    consoleParts << currentBuild.rawBuild.getLog(3000).join('\n')
                }

                def payload = [
                    job_name             : env.JOB_NAME,
                    build_number         : env.BUILD_NUMBER as Integer,
                    build_url            : env.BUILD_URL,
                    repo                 : env.GIT_URL ? env.GIT_URL.replaceFirst(/^.*github.com[\\/:]/, '').replaceFirst(/\\.git$/, '') : 'owner/repo',
                    branch               : env.BRANCH_NAME ?: env.GIT_BRANCH ?: 'main',
                    target_branch        : env.CHANGE_TARGET ?: env.BRANCH_NAME ?: 'main',
                    status               : currentBuild.currentResult ?: 'FAILED',
                    console_output       : consoleParts.join('\n\n'),
                    dependency_file_paths: dependencyFilePaths,
                    docker_file_paths    : dockerFilePaths
                ]

                writeFile(
                    file: 'jenkins_webhook_payload.json',
                    text: groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(payload))
                )

                sh '''
                    curl --fail --show-error --silent \
                      -X POST "$WEBHOOK_URL" \
                      -H "Content-Type: application/json" \
                      -H "x-webhook-secret: $WEBHOOK_SECRET" \
                      --data @jenkins_webhook_payload.json
                '''
            }
        }
    }
}
