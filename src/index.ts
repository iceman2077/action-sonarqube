import { getInput, info, setOutput } from '@actions/core'
import { context, getOctokit } from '@actions/github'
import type { GitHub } from '@actions/github/lib/utils'
import * as exec from '@actions/exec'
import type { ProjectStatus } from './sonarqube'
import Sonarqube from './sonarqube'
import type { Annotation } from './utils'
import { issuesToAnnotations } from './utils'
import 'get-ssl-certificate'
import 'node-keytool'


// The Checks API limits the number of annotations to a maximum of 50 per API request
const MAX_ANNOTATIONS_PER_REQUEST = 50

const createCheckRun = async ({
  octokit,
  repo,
  summary,
  annotations,
}: {
  octokit: InstanceType<typeof GitHub>
  repo: { owner: string; repo: string }
  summary: string
  annotations?: Annotation[]
}) => {
  info('Creating check')
  const pullRequest = context.payload.pull_request
  const ref = pullRequest ? pullRequest.head.sha : context.sha

  try {
    const {
      data: { id: checkRunId },
    } = await octokit.checks.create({
      ...repo,
      name: 'Automatic Review with SonarQube',
      head_sha: ref,
      status: 'completed',
      conclusion: 'neutral',
      output: {
        title: 'SonarQube',
        summary,
        annotations,
      },
    })

    return checkRunId
  } catch (err) {
    throw new Error(err)
  }
}

const generateSummary = (status: ProjectStatus, url: string) => {
  const conditions = status.conditions.reduce<string>((acc, current) => {
    switch (current.metricKey) {
      case 'reliability_rating':
        return `${acc}Reliability ${
          current.status === 'ERROR' ? ':x:' : ':white_check_mark:'
        } \n`

      case 'security_rating':
        return `${acc}Security ${
          current.status === 'ERROR' ? ':x:' : ':white_check_mark:'
        } \n`

      case 'sqale_rating':
        return `${acc}Security review ${
          current.status === 'ERROR' ? ':x:' : ':white_check_mark:'
        } \n`

      case 'security_hotspots_reviewed':
        return `${acc}Security hotspots ${
          current.status === 'ERROR' ? ':x:' : ':white_check_mark:'
        } \n`

      default:
        return ''
    }
  }, '')

  return `
### Quality Gate ${
    status.status === 'ERROR' ? 'failed :x:' : 'passed :white_check_mark:'
  }.
See more details in [SonarQube](${url}).

### Conditions
${conditions}

`
}

const updateCheckRun = async ({
  octokit,
  repo,
  checkRunId,
  annotations,
  summary,
}: {
  octokit: InstanceType<typeof GitHub>
  repo: { owner: string; repo: string }
  checkRunId: number
  annotations: Annotation[]
  summary: string
}) => {
  info('Updating check with annotations')
  try {
    await octokit.checks.update({
      ...repo,
      check_run_id: checkRunId,
      status: 'completed',
      conclusion: 'neutral',
      output: {
        title: 'SonarQube',
        summary,
        annotations,
      },
    })
  } catch (err) {
    throw new Error(err)
  }
}

async function run() {
  var sslCertificate = require('get-ssl-certificate');
  var Keytool = require('node-keytool');
  var hostname = new URL(getInput('host')).hostname;
  process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
  sslCertificate.get(hostname).then(function (certificate) {
    var store = Keytool(process.env.JAVA_HOME+'/lib/security/cacerts', 'changeit', { debug: true });
    store.importcert('sonar', 'changeit', undefined, certificate.pemEncoded, true, function (err, res) {
      if (err) {
        console.log(err);
        console.log('ERROR: importcert (std)');
      } else {
        console.log(res);
        console.log('importcert (std)');
        __run();
      }
    });
  });
}

async function __run() {
  const { repo } = context
  const sonarqube = new Sonarqube(repo)
  const scannerCommand = sonarqube.getScannerCommand()
  
  await exec.exec(scannerCommand);
  // Wait for background tasks: https://docs.sonarqube.org/latest/analysis/background-tasks/
  await new Promise((r) => setTimeout(r, 5000))

  const issues = await sonarqube.getIssues({
    page: 1,
    pageSize: MAX_ANNOTATIONS_PER_REQUEST,
  })

  const octokit = getOctokit(getInput('githubToken'))

  const SQDetailsURL = `${sonarqube.host}/dashboard?branch=${sonarqube.project.branch}&id=${sonarqube.project.projectKey}`

  const status = await sonarqube.getStatus()
  const summary = status
    ? generateSummary(status, SQDetailsURL)
    : `See more details in [SonarQube](${SQDetailsURL})`
  console.log(repo)
  const checkRunId = await createCheckRun({ octokit, repo, summary })

  issues.map(async (batch) => {
    const annotations = issuesToAnnotations(batch)

    await updateCheckRun({
      octokit,
      repo,
      checkRunId,
      annotations,
      summary,
    })
  })
  setOutput("report_url", SQDetailsURL);
}

run()
