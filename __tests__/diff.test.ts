import {Diff} from '../src/diff'
import {Package} from '../src/sbom'
import {describe, expect, jest, it} from '@jest/globals'
import {PackageURL} from 'packageurl-js'

describe('Diff', () => {
  describe('Package', () => {
    const pkg1 = new Package(
      PackageURL.fromString('pkg:deb/debian/adduser@3.118?arch=all')
    )
    const pkg2 = new Package(
      PackageURL.fromString('pkg:deb/debian/apt@2.2.4?arch=amd64')
    )

    it('no differences', () => {
      const diff = new Diff([pkg1], [pkg1])
      expect(diff.added.length).toBe(0)
      expect(diff.removed.length).toBe(0)
      expect(diff.changed.length).toBe(0)
    })

    it('checking equality, not references', () => {
      const pkg1Again = new Package(
        PackageURL.fromString('pkg:deb/debian/adduser@3.118?arch=all')
      )
      const diff = new Diff([pkg1], [pkg1Again])
      expect(diff.added.length).toBe(0)
      expect(diff.removed.length).toBe(0)
      expect(diff.changed.length).toBe(0)
    })

    it('added', () => {
      const diff = new Diff([pkg1], [pkg1, pkg2])
      expect(diff.added.length).toBe(1)
      expect(diff.removed.length).toBe(0)
      expect(diff.changed.length).toBe(0)
    })

    it('removed', () => {
      const diff = new Diff([pkg1, pkg2], [pkg1])
      expect(diff.added.length).toBe(0)
      expect(diff.removed.length).toBe(1)
      expect(diff.changed.length).toBe(0)
    })

    it('changed', () => {
      const olderPkg2 = new Package(
        PackageURL.fromString('pkg:deb/debian/apt@2.2.3?arch=amd64')
      )

      const diff = new Diff([pkg1, pkg2], [pkg1, olderPkg2])
      expect(diff.added.length).toBe(0)
      expect(diff.removed.length).toBe(0)
      expect(diff.changed.length).toBe(1)
      const entry = diff.changed[0]
      expect(entry.left).toBe(pkg2)
      expect(entry.right).toBe(olderPkg2)
    })
  })
})
