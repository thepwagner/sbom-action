import * as core from '@actions/core'
import {SBOM} from './sbom'
import {Octokit} from '@octokit/rest'
import type {PullRequestEvent} from '@octokit/webhooks-types'

export class GitHub {
  constructor(private readonly gh: Octokit) {}

  async postDiff(
    event: PullRequestEvent,
    base: SBOM,
    head: SBOM
  ): Promise<void> {
    core.info(`Comparing SBOMs ${base} ${head}`)

    const diff = this.purlDiff(base, head)
    core.info(`Compared SBOMs ${JSON.stringify(diff)}`)

    const purls = Object.keys(diff)
      .sort((a, b) => a.localeCompare(b))
      .map(purl => {
        const prefix = diff[purl] ? '+' : '-'
        return `${prefix}${purl}`
      })

    let body = '### Packages diff\n\n'
    body += `Base: \`${base.imageID}\`\n`
    body += `Head: \`${head.imageID}\`\n\n`

    if (purls.length) {
      body += '\n```\n'
      body += purls.join('\n')
      body += '\n```\n'
    }

    await this.gh.rest.issues.createComment({
      owner: event.repository.owner.login,
      repo: event.repository.name,
      issue_number: event.pull_request.number,
      body
    })
  }

  private purlDiff(base: SBOM, head: SBOM): Record<string, boolean> {
    const purlDiff = {} as Record<string, boolean>

    for (const pkg of head.packages) {
      const existing = base.packages.find(basePkg => basePkg.purl === pkg.purl)
      if (!existing) {
        purlDiff[pkg.purl] = true
      }
    }

    for (const pkg of base.packages) {
      const retained = head.packages.find(headPkg => headPkg.purl === pkg.purl)
      if (!retained) {
        purlDiff[pkg.purl] = false
      }
    }

    return purlDiff
  }
}
