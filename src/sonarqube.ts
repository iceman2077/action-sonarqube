import type { AxiosInstance } from 'axios'
import axios from 'axios'
import { getInput } from '@actions/core'
import 'get-ssl-certificate'
import 'node-keytool'

export interface Issue {
  key: string
  rule: string
  component: string
  message: string
  severity: 'INFO' | 'MINOR' | 'MAJOR' | 'CRITICAL' | 'BLOCKER'
  project: string
  line: number
  hash: string
  status: 'OPEN' | 'CONFIRMED' | 'REOPENED' | 'RESOLVED' | 'CLOSED'
  MESSAGE: string
  effort: string
  debt: string
  author: string
  tag: string[]
  creationDate: Date
  updateDate: Date
  type: 'CODE_SMELL' | 'BUG' | 'VULNERABILITY'
  organization: string
  scope: string
  textRange: {
    startLine: number
    endLine: number
    startOffset: number
    endOffset: number
  }
}
interface IssuesResponseAPI {
  total: number
  p: number
  ps: number
  paging: {
    pageIndex: number
    pageSize: number
    total: number
  }
  effortTotal: number
  debtTotal: number
  issues: [Issue]
}

export interface ProjectStatus {
  status: 'OK' | 'ERROR'
  conditions: Array<{
    status: 'OK' | 'ERROR'
    metricKey: string
    comparator: string
    errorThreshold: number
    actualValue: number
  }>
}

export interface ProjectStatusResponseAPI {
  projectStatus: ProjectStatus
}

export interface SonarCert{
  sonarCert: SonarCert
}
export default class Sonarqube {
  private http: AxiosInstance
  public host: string
  private token: string
  public project: {
    projectKey: string
    projectName: string
    projectBaseDir: string
    lintReport: string
    golangciLintReport: string
    flags: string
  }

  constructor(repo: { owner: string; repo: string }) {
    const info = this.getInfo(repo)

    this.host = info.host
    this.token = info.token
    this.project = info.project
    const tokenb64 = Buffer.from(`${this.token}:`).toString('base64')

    this.http = axios.create({
      baseURL: this.host,
      timeout: 10000,
      headers: {
        Authorization: `Basic ${tokenb64}`,
      },
    })
  }

  public getIssues = async ({
    pageSize,
    page,
    status = 'OPEN',
    result = [],
  }: {
    pageSize: number
    page: number
    status?: string
    result?: Array<[Issue]>
  }): Promise<Array<[Issue]>> => {
    try {
      const response = await this.http.get<IssuesResponseAPI>(
        `/api/issues/search?componentKeys=${this.project.projectKey}&statuses=${status}&ps=${pageSize}&p=${page}`
      )

      if (response.status !== 200 || !response.data) {
        return result
      }

      const {
        data: { issues },
      } = response

      result.push(issues)
      if (pageSize * page >= response.data.paging.total) {
        return result
      }

      return await this.getIssues({ pageSize, page: page + 1, result })
    } catch (err) {
      throw new Error(
        'Error getting project issues from SonarQube. Please make sure you provided the host and token inputs.'
      )
    }
  }

  public setSonarCert = async (): Promise<SonarCert | null> => {
    var sslCertificate = require('get-ssl-certificate');
    var Keytool = require('node-keytool');
    var hostname = new URL(this.host).hostname;
    console.log(hostname);
    sslCertificate.get(hostname).then(function (certificate) {
      console.log(certificate.pemEncoded);
      var store = Keytool(process.env.JAVA_HOME+'/lib/security/cacerts', 'changeit', { debug: false, storetype: 'JCEKS' });
      console.log(store);
      store.importcert('sonar', '', undefined, certificate.pemEncoded, true, function (err, res) {
        if (err) {
          console.log(err);
          console.log('ERROR: importcert (std)');
        } else {
          console.log(res);
          console.log('importcert (std)');
        }
      });
    });
    const SonarCert = null
    return SonarCert;
  }

  public getScannerCommand = () =>
    `sonar-scanner -Dsonar.projectKey=${
      this.project.projectKey
    } -Dsonar.projectName=${
      this.project.projectName
    } -Dsonar.sources=. -Dsonar.projectBaseDir=${
      this.project.projectBaseDir
    } -Dsonar.login=${this.token} -Dsonar.host.url=${this.host} ${
      this.project.lintReport
        ? `-Dsonar.eslint.reportPaths=${this.project.lintReport}`
        : ''
    } ${
      this.project.golangciLintReport
        ? `-Dsonar.go.golangci-lint.reportPaths=${this.project.golangciLintReport}`
        : ''
    } ${
      this.project.flags ? this.project.flags : ''
    }`

  public getStatus = async (): Promise<ProjectStatus | null> => {
    const response = await this.http.get<ProjectStatusResponseAPI>(
      `/api/qualitygates/project_status?projectKey=${this.project.projectKey}`
    )

    if (response.status !== 200 || !response.data) {
      return null
    }

    const {
      data: { projectStatus },
    } = response

    return projectStatus
  }

  private getInfo = (repo: { owner: string; repo: string }) => ({
    project: {
      projectKey: getInput('projectKey')
        ? getInput('projectKey')
        : `${repo.owner}-${repo.repo}`,
      projectName: getInput('projectName')
        ? getInput('projectName')
        : `${repo.owner}-${repo.repo}`,
      projectBaseDir: getInput('projectBaseDir'),
      lintReport: getInput('lintReport'),
      golangciLintReport: getInput('golangciLintReport'),
      flags: getInput('flags')
    },
    host: getInput('host'),
    token: getInput('token'),
  })
}
