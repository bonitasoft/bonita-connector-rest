timestamps {
    ansiColor('xterm') {
        node {
            stage('Setup') {
                checkout scm
            }

            stage('Build') {
                try {
                    sh "./mvnw clean verify -Djvm=${env.JAVA_HOME_11}/bin/java"
                    archiveArtifacts 'target/bonita-connector-rest-*.zip'
                } finally {
                    junit '**/target/surefire-reports/*.xml'
                }
            }
        }
    }
}
