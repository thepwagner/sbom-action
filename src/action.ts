import * as core from '@actions/core'
import {CosignSBOMLoader} from './cosign'
import {SBOMLoader, SBOMParser} from './sbom'
import type {PullRequestEvent, WebhookEvent} from '@octokit/webhooks-types'
import {CycloneDXParser} from './cyclonedx'
import {readFile} from 'fs/promises'
import {GitHub} from './github'
import {Octokit} from '@octokit/rest'

export class Handler {
  constructor(
    private readonly parser: SBOMParser,
    private readonly loader: SBOMLoader,
    private readonly gh: GitHub
  ) {}

  async onEvent(eventName: string, event: WebhookEvent): Promise<void> {
    core.debug(`Received "${eventName}" event: ${JSON.stringify(event)}`)

    switch (eventName) {
      case 'pull_request':
        return this.onPullRequestEvent(event as PullRequestEvent)

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

    const localSBOMdata = await readFile(core.getInput('sbom'), 'utf8')
    const localSBOM = this.parser.parse(localSBOMdata)

    const baseImageID = core.getInput('base-image')
    core.info(`Loading base image: ${baseImageID}`)
    const baseSBOM = await this.loader.load(baseImageID)

    await this.gh.postDiff(event, baseSBOM, localSBOM)
  }
}

function getLocalParser(): SBOMParser {
  return new CycloneDXParser()
}

function getRemoteLoader(): SBOMLoader {
  return new CosignSBOMLoader()
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
