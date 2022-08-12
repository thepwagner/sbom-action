import {CycloneDXParser} from '../src/cyclonedx'
import {describe, expect, it} from '@jest/globals'
import {readFile} from 'fs/promises'

describe('CycloneDXParser', () => {
  const parser = new CycloneDXParser()

  it('parses syft fixture', async () => {
    const doc = await readFile('__tests__/fixtures/cyclonedx.syft.json', 'utf8')
    const sbom = parser.parse(doc)

    expect(sbom.imageID).toBe(
      'ghcr.io/thepwagner-org/debian-bullseye:9ec73cc052f9acf1ec792ff5d23e1b14d50fc585'
    )
    expect(sbom.imageDigest).toBe(
      'sha256:27c13a70b81a3d6058ff0a456481012f97f34e0130a2711c5090418332c7383f'
    )
    expect(sbom.packages).toHaveLength(96)
    expect(sbom.packages[0].purl.toString()).toBe(
      'pkg:deb/debian/adduser@3.118'
    )
  })

  it('parses trivy fixture', async () => {
    const doc = await readFile(
      '__tests__/fixtures/cyclonedx.trivy.json',
      'utf8'
    )
    const sbom = parser.parse(doc)

    expect(sbom.imageID).toBe('debian:bullseye-20211220-slim')
    expect(sbom.imageDigest).toBe(
      'sha256:b0d53c872fd640c2af2608ba1e693cfc7dedea30abcd8f584b23d583ec6dadc7'
    )
    expect(sbom.packages).toHaveLength(96)
    expect(sbom.packages[0].purl.toString()).toBe(
      'pkg:deb/debian/adduser@3.118'
    )
    expect(sbom.vulnerabilities).toHaveLength(62)
    expect(sbom.vulnerabilities[0].cve).toBe('CVE-2004-0971')
  })
})
