timestamps {
        node {
                stage('Setup') {
                    checkout scm
                }

                stage('Release') {
                       withCredentials([usernamePassword(
                            credentialsId: 'github',
                            passwordVariable: 'GIT_PASSWORD',
                            usernameVariable: 'GIT_USERNAME')]) {
                                sh './mvnw release:prepare release:perform -B -DaltDeploymentRepository=${env.ALT_DEPLOYMENT_REPOSITORY_SNAPSHOTS}'
                       }
                }
            }
}
