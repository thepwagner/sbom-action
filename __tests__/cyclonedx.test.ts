import {CycloneDXParser} from '../src/cyclonedx'
import {describe, expect, it} from '@jest/globals'
import {readFileSync} from 'fs'

describe('CycloneDXParser', () => {
  const parser = new CycloneDXParser()

  it('parses fixture', () => {
    const doc = readFileSync('__tests__/fixtures/cyclonedx.json', 'utf8')
    const sbom = parser.parse(doc)

    expect(sbom.imageID).toBe('ghcr.io/thepwagner-org/debian-bullseye:9ec73cc052f9acf1ec792ff5d23e1b14d50fc585')
    expect(sbom.imageDigest).toBe('sha256:27c13a70b81a3d6058ff0a456481012f97f34e0130a2711c5090418332c7383f')
    expect(sbom.packages).toHaveLength(96)
    expect(sbom.packages[0].purl).toBe(
      'pkg:deb/debian/adduser@3.118?arch=all&distro=debian-11'
    )
  })
})
