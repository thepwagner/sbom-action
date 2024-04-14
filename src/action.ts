import * as core from '@actions/core'
import {CosignSBOMLoader} from './cosign'
import {SBOM, SBOMLoader, SBOMParser} from './sbom'
import type {PullRequestEvent, WebhookEvent} from '@octokit/webhooks-types'
import {CycloneDXParser} from './cyclonedx'
import {readFile} from 'fs/promises'
import {Diff} from './diff'
import {GitHub} from './github'
import {Octokit} from '@octokit/rest'

export class Handler {
  constructor(
    private readonly parser: SBOMParser,
    private readonly loader: SBOMLoader,
    private readonly gh: GitHub
  ) {}

  async onEvent(eventName: string, event: WebhookEvent): Promise<void> {
    core.info(`Received "${eventName}" event: ${JSON.stringify(event)}`)

    switch (eventName) {
      case 'pull_request':
        return this.onPullRequestEvent(event as PullRequestEvent)

      case 'schedule':
      case 'workflow_dispatch':
        return this.onScheduleEvent()

      case 'test':
      case '':
        return
    }
  }

  private async onPullRequestEvent(event: PullRequestEvent): Promise<void> {
    switch (event.action) {
      case 'opened':
      case 'synchronize':
        break
      default:
        return
    }

    const localSBOM = await this.loadLocalSBOM()
    const baseSBOM = await this.loadBaseSBOM()
    await this.gh.postDiff(event, baseSBOM, localSBOM)
  }

  private async onScheduleEvent(): Promise<void> {
    const localSBOM = await this.loadLocalSBOM()
    const baseSBOM = await this.loadBaseSBOM()

    const pkgDiff = new Diff(baseSBOM.packages, localSBOM.packages)
    const vulnDiff = new Diff(
      baseSBOM.vulnerabilities,
      localSBOM.vulnerabilities
    )

    core.setOutput('packages-changed', !pkgDiff.empty())
    core.setOutput('vulnerabilities-changed', !vulnDiff.empty())
  }

  private async loadLocalSBOM(): Promise<SBOM> {
    const localSBOMPath = core.getInput('sbom')
    const localSBOMdata = await readFile(localSBOMPath, 'utf8')
    core.info(`Loading local SBOM: ${localSBOMPath}`)
    return this.parser.parse(localSBOMdata)
  }

  private async loadBaseSBOM(): Promise<SBOM> {
    const baseImageID = core.getInput('base-image')
    core.info(`Loading base image: ${baseImageID}`)
    return await this.loader.load(baseImageID)
  }
}

function getLocalParser(): SBOMParser {
  return new CycloneDXParser()
}

function getRemoteLoader(): SBOMLoader {
  return new CosignSBOMLoader(
    true,
    core.getInput('certificate-identity-regexp'),
    core.getInput('certificate-oidc-issuer-regexp')
  )
}

function getGitHub(): GitHub {
  const auth = core.getInput('token')
  const okto = new Octokit({auth})
  return new GitHub(okto)
}

export function newHandler(): Handler {
  const parser = getLocalParser()
  const loader = getRemoteLoader()
  const gh = getGitHub()
  return new Handler(parser, loader, gh)
}
