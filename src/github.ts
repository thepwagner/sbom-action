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

    const body = this.renderBody(base, head)
    if (body === '') {
      return
    }

    await this.gh.rest.issues.createComment({
      owner: event.repository.owner.login,
      repo: event.repository.name,
      issue_number: event.pull_request.number,
      body
    })
  }

  renderBody(base: SBOM, head: SBOM): string {
    const pkgDiff = new Diff(base.packages, head.packages)
    const vulnDiff = new Diff(base.vulnerabilities, head.vulnerabilities)

    if (pkgDiff.empty() && vulnDiff.empty()) {
      return ''
    }

    let body = '### SBOM diff\n\n'
    body += `Base: \`${base.imageID}\`\n`
    body += `Head: \`${head.imageID}\`\n\n`

    core.info(`Compared SBOM packages ${JSON.stringify(pkgDiff)}`)
    if (!pkgDiff.empty()) {
      body += '#### 📦 Packages\n\n'

      body += '| Package | Old | New |\n'
      body += '|---------|-----|-----|\n'

      for (const pkg of pkgDiff.added) {
        body += `| \`${decodeURIComponent(pkg.key())}\` `
        body += `| `
        body += `| \`${pkg.purl.version}\` `
        body += `|\n`
      }

      for (const pkg of pkgDiff.removed) {
        body += `| \`${decodeURIComponent(pkg.key())}\` `
        body += `| \`${pkg.purl.version}\` `
        body += `| `
        body += `|\n`
      }

      for (const pkg of pkgDiff.changed) {
        body += `| \`${decodeURIComponent(pkg.left.key())}\` `
        body += `| \`${pkg.left.purl.version}\` `
        body += `| \`${pkg.right.purl.version}\` `
        body += `|\n`
      }
      body += '\n\n'
    }

    core.info(`Compared SBOM vulnerabilities ${JSON.stringify(vulnDiff)}`)
    if (!vulnDiff.empty()) {
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

    return body
  }
}
