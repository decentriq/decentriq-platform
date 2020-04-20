def checkoutGitBranchOrMaster(url) {
    def branch = resolveScm source: [$class: 'GitSCMSource', credentialsId: 'decentriq-bot-ci-token', remote: url, traits: [[$class: 'jenkins.plugins.git.traits.BranchDiscoveryTrait']]], targets: [env.CHANGE_BRANCH, 'master']
    def directory = "__${url.split('/').last()}"
    dir(directory) {
        checkout branch
    }
    return directory
}

pipeline {
    agent any
    options { timestamps() }

    stages {
        stage('Checkout delta') {
            steps {
                script {
                    def delta_dir = checkoutGitBranchOrMaster 'https://github.com/decentriq/delta.git'
                    dir(delta_dir) {
                        load 'integration-tests/Test.groovy'
                    }
                }
            }
        }
    }
}
