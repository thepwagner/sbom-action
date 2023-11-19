import {SBOM, SBOMLoader} from './sbom'
import {CycloneDXParser, CycloneBOM} from './cyclonedx'
import {exec} from '@actions/exec'

export class CosignSBOMLoader implements SBOMLoader {
  private cyclonedx = new CycloneDXParser()

  /** Wrap @actions/exec, awkwardly accessible for tests to replace. */
  exec = async (commandLine: string, args: string[]): Promise<string> => {
    let out = ''
    await exec(commandLine, args, {
      listeners: {
        stdout: data => {
          out += data.toString()
        }
      },
      env: {
        PATH: process.env.PATH || ''
      }
    })
    return out
  }

  constructor(
    private readonly fromAttestations = true,
    private readonly certificateIdentityRegExp = '.*',
    private readonly certificateOidcIssuerRegExp = '.*'
  ) {}

  async load(imageID: string): Promise<SBOM> {
    if (this.fromAttestations) {
      return this.loadFromAttestation(imageID)
    }
    throw new Error('TODO: implement loading attached SBOMs')
  }

  private async loadFromAttestation(imageID: string): Promise<SBOM> {
    const out = await this.exec('cosign', [
      'verify-attestation',
      '--type',
      'cyclonedx',
      '--certificate-identity-regexp',
      this.certificateIdentityRegExp,
      '--certificate-oidc-issuer-regexp',
      this.certificateOidcIssuerRegExp,
      imageID
    ])

    const attestation = JSON.parse(out) as Attestation
    const payload = Buffer.from(attestation.payload, 'base64').toString()
    const predicate = JSON.parse(payload) as Predicate

    switch (predicate.predicateType) {
      case 'cosign.sigstore.dev/attestation/v1':
        // Assume custom predicates are CycloneDX, since SPDX has been supported longer
        return this.cyclonedx.parse(predicate.predicate['Data'])
      case 'https://cyclonedx.org/schema':
        return this.cyclonedx.extract(predicate.predicate['Data'] as CycloneBOM)
      // TODO: spdx?
      default:
        throw new Error(`Unsupported predicate: ${predicate.predicateType}`)
    }
  }
}

type Attestation = {
  payloadType: string
  payload: string
}

type Predicate = {
  _type: string
  predicateType: string
  predicate: {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [key: string]: any
  }
}
