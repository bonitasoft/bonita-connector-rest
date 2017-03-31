def mvn(args) {
    sh "${tool 'maven'}/bin/mvn ${args}"
}

node {
    checkout scm

    stage('build')
    try {
        mvn 'clean verify'
        archive 'target/bonita-connector-rest-*.zip'
    } finally {
        junit '**/target/surefire-reports/*.xml'
    }
}
