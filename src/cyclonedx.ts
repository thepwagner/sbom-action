import {Package, Vulnerability, SBOM, SBOMParser} from './sbom'
import {PackageURL} from 'packageurl-js'
import * as cdx from '@cyclonedx/cyclonedx-library'

export class CycloneDXParser implements SBOMParser {
  /** Parse from string. */
  parse(sbom: string): SBOM {
    const bom = JSON.parse(sbom) as cdx.Models.Bom
    return this.extract(bom)
  }

  /** Extract from object. */
  extract(bom: cdx.Models.Bom): SBOM {
    if (!bom?.metadata?.component) {
      throw new Error('metadata component required')
    }
    const imageID = bom.metadata.component.name

    let imageDigest: string
    if (bom.metadata.component.version) {
      imageDigest = bom.metadata.component.version
    } else if (bom.metadata.component.purl) {
      const purl = PackageURL.fromString(bom.metadata.component.purl.toString())
      imageDigest = purl.version || ''
    } else {
      imageDigest = ''
    }

    const packages = [] as Package[]
    for (const c of bom.components) {
      if (!c.purl) {
        continue
      }
      packages.push({purl: c.purl.toString()})
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
