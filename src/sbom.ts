import {PackageURL} from 'packageurl-js'

export interface HasKey {
  key(): string
}

export class Package implements HasKey {
  constructor(readonly purl: PackageURL) {}

  key(): string {
    return (
      (this.purl.type || '') +
      (this.purl.namespace || '') +
      (this.purl.name || '')
    )
  }
}

export class Vulnerability implements HasKey {
  constructor(readonly cve: string) {}

  key(): string {
    return this.cve
  }
}

export type SBOM = {
  imageID: string
  imageDigest: string
  packages: Package[]
  vulnerabilities: Vulnerability[]
}

export interface SBOMLoader {
  load(imageID: string): Promise<SBOM>
}

export interface SBOMParser {
  parse(sbom: string): SBOM
}
