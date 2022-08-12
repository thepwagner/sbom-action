import * as core from '@actions/core'
import {SBOM} from './sbom'
import {Octokit} from '@octokit/rest'
import type {PullRequestEvent} from '@octokit/webhooks-types'
import {Diff} from './diff'

export class GitHub {
  constructor(private readonly gh: Octokit) {}

  async postDiff(
    event: PullRequestEvent,
    base: SBOM,
    head: SBOM
  ): Promise<void> {
    core.info(`Comparing SBOMs ${base} ${head}`)

    const pkgDiff = new Diff(base.packages, head.packages)
    const vulnDiff = new Diff(base.vulnerabilities, head.vulnerabilities)

    if (pkgDiff.empty() && vulnDiff.empty()) {
      return
    }

    let body = '### SBOM diff\n\n'
    body += `Base: \`${base.imageID}\`\n`
    body += `Head: \`${head.imageID}\`\n\n`

    core.info(`Compared SBOM packages ${JSON.stringify(pkgDiff)}`)
    if (!pkgDiff.empty()) {
      body += '#### 📦 Packages\n\n'

      if (pkgDiff.added.length > 0) {
        body += '**Added**:\n\n'
        for (const pkg of pkgDiff.added) {
          body += `- \`${pkg.purl.toString()}\`\n`
        }
        body += '\n'
      }
      if (pkgDiff.removed.length > 0) {
        body += '**Removed**:\n\n'
        for (const pkg of pkgDiff.removed) {
          body += `- \`${pkg.purl.toString()}\`\n`
        }
        body += '\n'
      }
      if (pkgDiff.changed.length > 0) {
        body += '**Changed**:\n\n'
        for (const pkg of pkgDiff.changed) {
          body += `- \`${pkg.left.key()}\` - \`${
            pkg.left.purl.version
          }\` to \`${pkg.right.purl.version}\`\n`
        }
        body += '\n'
      }
    }

    core.info(`Compared SBOM vulnerabilities ${JSON.stringify(vulnDiff)}`)
    if (!pkgDiff.empty()) {
      body += '#### ⚠️ Vulnerabilities\n\n'
      if (vulnDiff.added.length > 0) {
        body += '**Detected**:\n\n'
        for (const vuln of vulnDiff.added) {
          body += `- \`${vuln.cve}\`\n`
        }
        body += '\n'
      }
      if (vulnDiff.removed.length > 0) {
        body += '**Fixed**:\n\n'
        for (const vuln of vulnDiff.removed) {
          body += `- \`${vuln.cve}\`\n`
        }
        body += '\n'
      }
    }

    await this.gh.rest.issues.createComment({
      owner: event.repository.owner.login,
      repo: event.repository.name,
      issue_number: event.pull_request.number,
      body
    })
  }
}
