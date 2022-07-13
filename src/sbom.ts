export type Package = {
  purl: string
}

export type SBOM = {
  packages: Package[]
}

export interface SBOMLoader {
  load(imageID: string): Promise<SBOM>
}

export interface SBOMParser {
  parse(sbom: string): SBOM
}
