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

    let body = '### SBOM diff\n\n'
    body += `Base: \`${base.imageID}\`\n`
    body += `Head: \`${head.imageID}\`\n\n`

    const pkgDiff = this.purlDiff(base, head)
    core.info(`Compared SBOM packages ${JSON.stringify(pkgDiff)}`)
    const purls = Object.keys(pkgDiff)
      .sort((a, b) => a.localeCompare(b))
      .map(purl => {
        const prefix = pkgDiff[purl] ? '+' : '-'
        return `${prefix}${purl}`
      })
    if (purls.length) {
      body += '#### Packages\n\n'
      body += '\n```\n'
      body += purls.join('\n')
      body += '\n```\n'
    }

    const vulnDiff = this.vulnDiff(base, head)
    core.info(`Compared SBOM vulnerabilities ${JSON.stringify(vulnDiff)}`)
    const cves = Object.keys(vulnDiff)
      .sort((a, b) => a.localeCompare(b))
      .map(cve => {
        const prefix = vulnDiff[cve] ? '+' : '-'
        return `${prefix}${cve}`
      })
    if (cves.length) {
      body += '#### Vulnerabilities\n\n'
      body += '\n```\n'
      body += cves.join('\n')
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

  private vulnDiff(base: SBOM, head: SBOM): Record<string, boolean> {
    const vulnDiff = {} as Record<string, boolean>

    for (const vuln of head.vulnerabilities) {
      const existing = base.vulnerabilities.find(
        baseVuln => baseVuln.cve === vuln.cve
      )
      if (!existing) {
        vulnDiff[vuln.cve] = true
      }
    }

    for (const vuln of base.vulnerabilities) {
      const retained = head.vulnerabilities.find(
        headVuln => headVuln.cve === vuln.cve
      )
      if (!retained) {
        vulnDiff[vuln.cve] = false
      }
    }

    return vulnDiff
  }
}
