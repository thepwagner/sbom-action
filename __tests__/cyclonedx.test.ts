import {CycloneDXParser} from '../src/cyclonedx'
import {describe, expect, it} from '@jest/globals'
import {readFileSync} from 'fs'

describe('CycloneDXParser', () => {
  const parser = new CycloneDXParser()

  it('parses fixture', () => {
    const doc = readFileSync('__tests__/fixtures/cyclonedx.json', 'utf8')
    const sbom = parser.parse(doc)

    expect(sbom.packages).toHaveLength(96)
    expect(sbom.packages[0].purl).toBe('pkg:deb/debian/adduser@3.118?arch=all&distro=debian-11')
  })
})
