import {describe, expect, it} from '@jest/globals'
import {PackageURL} from 'packageurl-js'
import {GitHub} from '../src/github'
import {Package, SBOM, Vulnerability} from '../src/sbom'

describe('GitHub', () => {
  describe('renderBody', () => {
    const pkg1 = new Package(
      PackageURL.fromString('pkg:deb/debian/adduser@3.118?arch=all')
    )

    const emptyBOM: SBOM = {
      imageID: 'empty',
      imageDigest: 'digest1',
      packages: [],
      vulnerabilities: []
    }
    const onePkg: SBOM = {
      imageID: 'one-package',
      imageDigest: 'digest2',
      packages: [pkg1],
      vulnerabilities: []
    }
    const oneVuln: SBOM = {
      imageID: 'one-vulnerability',
      imageDigest: 'digest3',
      packages: [pkg1],
      vulnerabilities: [new Vulnerability('CVE-2022-0001')]
    }
    const boms = [emptyBOM, onePkg, oneVuln]

    const gh = new GitHub(null as any)

    it('returns empty when empty', () => {
      boms.forEach(bom => {
        const body = gh.renderBody(bom, bom)
        expect(body).toBe('')
      })
    })

    describe('package diff', () => {
      it('lists added packages', () => {
        const body = gh.renderBody(emptyBOM, onePkg)
        expect(body).toContain('Packages')
        expect(body).toContain('| `pkg:deb/debian/adduser` | | `3.118` |')
        expect(body).not.toContain('Vulnerabilities')
      })

      it('lists removed packages', () => {
        const body = gh.renderBody(onePkg, emptyBOM)
        expect(body).toContain('Packages')
        expect(body).toContain('| `pkg:deb/debian/adduser` | `3.118` | |')
        expect(body).not.toContain('Vulnerabilities')
      })

      it('decodes packages', () => {
        const npmPkg = new Package(
          PackageURL.fromString('pkg:npm/%40types/node@18.7.3')
        )
        const oneNpmPkg: SBOM = {
          imageID: 'one-npm',
          imageDigest: 'digest4',
          packages: [npmPkg],
          vulnerabilities: []
        }
        const body = gh.renderBody(emptyBOM, oneNpmPkg)
        expect(body).toContain('pkg:npm/@types/node')
        expect(body).not.toContain('pkg:npm/%40types/node')
      })
    })

    describe('vuln diff', () => {
      it('lists detected vulns', () => {
        const body = gh.renderBody(emptyBOM, oneVuln)
        expect(body).toContain('Vulnerabilities')
        expect(body).toContain('Detected')
        expect(body).toContain('CVE-2022-0001')
      })

      it('lists fixed vulns', () => {
        const body = gh.renderBody(oneVuln, emptyBOM)
        expect(body).toContain('Vulnerabilities')
        expect(body).toContain('Fixed')
        expect(body).toContain('CVE-2022-0001')
      })
    })
  })
})
