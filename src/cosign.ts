import {SBOM, SBOMLoader} from './sbom'
import {CycloneDXParser} from './cyclonedx'
import {exec} from '@actions/exec'

export class CosignSBOMLoader implements SBOMLoader {
  private cyclonedx = new CycloneDXParser()

  exec = async (commandLine: string, args: string[]): Promise<string> => {
    let out = ''
    await exec(commandLine, args, {
      listeners: {
        stdout: data => {
          out += data.toString()
        }
      },
      env: {
        PATH: process.env.PATH || '',
        COSIGN_EXPERIMENTAL: '1'
      }
    })
    return out
  }

  constructor(private readonly fromAttestations = true) {}

  async load(imageID: string): Promise<SBOM> {
    if (this.fromAttestations) {
      return this.loadFromAttestation(imageID)
    }
    throw new Error('FIXME: implement loading attached SBOMs')
  }

  private async loadFromAttestation(imageID: string): Promise<SBOM> {
    const out = await this.exec('cosign', ['verify-attestation', imageID])

    const attestation = JSON.parse(out) as Attestation
    const payload = Buffer.from(attestation.payload, 'base64').toString()
    const predicate = JSON.parse(payload) as Predicate

    switch (predicate.predicateType) {
      case 'cosign.sigstore.dev/attestation/v1':
        return this.cyclonedx.parse(predicate.predicate['Data'])
      case 'https://cyclonedx.org/schema':
        // TODO: untested, cosign has not released this yet - https://github.com/sigstore/cosign/pull/1977
        return this.cyclonedx.parse(predicate.predicate['Data'])
      // TODO: spdx
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
