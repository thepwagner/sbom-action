import {Package, SBOM, SBOMParser, Vulnerability} from './sbom'
import {PackageURL} from 'packageurl-js'

export class CycloneBOM {
  readonly metadata?: Metadata
  readonly components: Component[] = []
  readonly vulnerabilities: CycloneVulnerability[] = []
}

class Metadata {
  readonly component?: Component
}

class Component {
  readonly version?: string
  readonly purl?: string
  constructor(readonly name: string) {}
}

class CycloneVulnerability {
  readonly id?: string
}

export class CycloneDXParser implements SBOMParser {
  /** Parse from string. */
  parse(sbom: string): SBOM {
    const bom = JSON.parse(sbom) as CycloneBOM
    return this.extract(bom)
  }

  /** Extract from object. */
  extract(bom: CycloneBOM): SBOM {
    if (!bom?.metadata?.component) {
      throw new Error('metadata component required')
    }
    const imageID = bom.metadata.component.name

    let imageDigest = ''
    if (bom.metadata.component.version) {
      imageDigest = bom.metadata.component.version
    } else if (bom.metadata.component.purl) {
      const purl = PackageURL.fromString(bom.metadata.component.purl)
      imageDigest = purl.version || ''
    }

    const packages = [] as Package[]
    for (const component of bom.components) {
      if (!component.purl) {
        continue
      }

      // Fix any versions that aren't encoded
      let purlRaw = component.purl
      const url = new URL(purlRaw)
      const path = url.pathname.trim().replace(/^\/+/g, '')
      const index = path.indexOf('@')
      if (index !== -1) {
        const rawVersion = path.substring(index + 1)
        const encodedVersion = encodeURIComponent(
          decodeURIComponent(rawVersion)
        )
          .replace(/%3A/g, ':')
          .replace(/%2B/g, '+')

        purlRaw = component.purl.replace(rawVersion, encodedVersion)
      }

      const purl = PackageURL.fromString(purlRaw)
      purl.qualifiers = null // the 'distro' qualifier is annoying, don't need any of them
      packages.push(new Package(purl))
    }
    packages.sort((a, b) => a.purl.toString().localeCompare(b.purl.toString()))

    const vulnerabilities = [] as Vulnerability[]
    if (bom.vulnerabilities) {
      for (const vuln of bom.vulnerabilities) {
        if (!vuln.id) {
          continue
        }
        vulnerabilities.push(new Vulnerability(vuln.id))
      }
      vulnerabilities.sort((a, b) => a.cve.localeCompare(b.cve))
    }

    return {imageID, imageDigest, packages, vulnerabilities}
  }
}
