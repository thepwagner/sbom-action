import {CosignSBOMLoader} from '../src/cosign'
import {describe, expect, jest, it} from '@jest/globals'
import {fn} from 'jest-mock'
import {readFile} from 'fs/promises'

describe('CosignSBOMLoader', () => {
  describe('fromAttestation', () => {
    const loader = new CosignSBOMLoader(true)
    const mockExec = fn()
    loader.exec = mockExec as () => Promise<string>

    it('loads cyclonedx from custom predicate', async () => {
      const attestation = await readFile(
        '__tests__/fixtures/cyclonedx.customattestation.json',
        'utf8'
      )
      mockExec.mockReturnValue(attestation)
      const imageID =
        'ghcr.io/thepwagner-org/debian-bullseye:9ec73cc052f9acf1ec792ff5d23e1b14d50fc585'
      const sbom = await loader.load(imageID)
      expect(mockExec).toHaveBeenCalledWith('cosign', [
        'verify-attestation',
        '--type',
        'cyclonedx',
        '--certificate-identity-regexp',
        '.*',
        '--certificate-oidc-issuer-regexp',
        '.*',
        imageID
      ])
      expect(sbom.packages).toHaveLength(96)
    })

    it('loads cyclonedx from cyclonedx predicate', async () => {
      const attestation = await readFile(
        '__tests__/fixtures/cyclonedx.cyclonedxattestation.json',
        'utf8'
      )
      mockExec.mockReturnValue(attestation)
      const imageID =
        'ghcr.io/thepwagner-org/debian-bullseye:c8c63081113e24f0af78737451a8d916444291ba'
      const sbom = await loader.load(imageID)
      expect(mockExec).toHaveBeenCalledWith('cosign', [
        'verify-attestation',
        '--type',
        'cyclonedx',
        '--certificate-identity-regexp',
        '.*',
        '--certificate-oidc-issuer-regexp',
        '.*',
        imageID
      ])
      expect(sbom.packages).toHaveLength(96)
    })

    it('loads cyclonedx from cyclonedx/bom predicate', async () => {
      const attestation = await readFile(
        '__tests__/fixtures/cyclonedx.cyclonebom.json',
        'utf8'
      )
      mockExec.mockReturnValue(attestation)
      const imageID =
        'ghcr.io/thepwagner-org/debian-bullseye:c8c63081113e24f0af78737451a8d916444291ba'
      const sbom = await loader.load(imageID)
      expect(mockExec).toHaveBeenCalledWith('cosign', [
        'verify-attestation',
        '--type',
        'cyclonedx',
        '--certificate-identity-regexp',
        '.*',
        '--certificate-oidc-issuer-regexp',
        '.*',
        imageID
      ])
      expect(sbom.packages).toHaveLength(88)
    })
  })
})
