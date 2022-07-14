import {Package, SBOM, SBOMParser} from './sbom'

import * as cdx from '@cyclonedx/cyclonedx-library'

export class CycloneDXParser implements SBOMParser {
  parse(sbom: string): SBOM {
    const bom = JSON.parse(sbom) as cdx.Models.Bom

    if (!bom?.metadata?.component) {
      throw new Error('metadata component required')
    }
    const imageID = bom.metadata.component.name
    const imageDigest = bom.metadata.component.version || ''

    const packages = [] as Package[]
    for (const c of bom.components) {
      if (!c.purl) {
        continue
      }
      packages.push({purl: c.purl.toString()} as Package)
    }
    packages.sort((a, b) => a.purl.localeCompare(b.purl))

    return {imageID, imageDigest, packages}
  }
}
