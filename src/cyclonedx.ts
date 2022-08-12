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
    for (const c of bom.components) {
      if (!c.purl) {
        continue
      }
      packages.push({purl: c.purl})
    }
    packages.sort((a, b) => a.purl.localeCompare(b.purl))

    const vulnerabilities = [] as Vulnerability[]
    if (bom.vulnerabilities) {
      for (const v of bom.vulnerabilities) {
        if (!v.id) {
          continue
        }
        vulnerabilities.push({cve: v.id})
      }
      vulnerabilities.sort((a, b) => a.cve.localeCompare(b.cve))
    }

    return {imageID, imageDigest, packages, vulnerabilities}
  }
}
