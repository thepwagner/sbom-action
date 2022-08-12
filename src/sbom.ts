export type Package = {
  purl: string
}

export type Vulnerability = {
  cve: string
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
