timestamps {
    ansiColor('xterm') {
        node {
            stage('Setup') {
                checkout scm
            }

            stage('Release') {
                sh './mvnw release:prepare -B'
            }
        }
    }
}