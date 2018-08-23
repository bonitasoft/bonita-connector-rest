timestamps {
    ansiColor('xterm') {
        node {
            stage('Setup') {
                configGitCredentialHelper()
                checkout scm
            }

            stage('Release') {
                sh './mvnw release:prepare -B'
            }
        }
    }
}

def configGitCredentialHelper() {
    sh """#!/bin/bash +x
        set -e
        echo "Using the git cache credential helper to be able to perform native git commands without passing authentication parameters"
        # Timeout in seconds, ensure we have enough time to perform the whole process between the initial clone and the final branch push
        git config --global credential.helper 'cache --timeout=18000'
    """    
}
