import {HasKey} from './sbom'

export class DiffEntry<T> {
  constructor(readonly left: T, readonly right: T) {}
}
export class Diff<T extends HasKey> {
  readonly added: T[] = []
  readonly removed: T[] = []
  readonly changed: DiffEntry<T>[] = []

  constructor(left: T[], right: T[]) {
    const leftMapped = new Map(left.map(t => [t.key(), t]))
    const rightMapped = new Map(right.map(t => [t.key(), t]))
    for (const [key, value] of leftMapped) {
      const rightValue = rightMapped.get(key)
      if (rightValue === undefined) {
        this.removed.push(value)
      } else if (rightValue !== value) {
        this.changed.push(new DiffEntry(value, rightValue))
      }
    }

    for (const [key, value] of rightMapped) {
      if (!leftMapped.has(key)) {
        this.added.push(value)
      }
    }
  }

  empty(): boolean {
    return (
      this.added.length === 0 &&
      this.removed.length === 0 &&
      this.changed.length === 0
    )
  }
}
