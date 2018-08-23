timestamps {
    ansiColor('xterm') {
        node {
              withCredentials([usernamePassword(
                    credentialsId: 'github',
                    passwordVariable: 'GIT_PASSWORD',
                    usernameVariable: 'GIT_USERNAME')]) {
                stage('Setup') {
                    checkout scm
                }

                stage('Release') {
                    sh './mvnw release:prepare -B'
                }
            }
        }
    }
}
