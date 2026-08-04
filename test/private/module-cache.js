'use strict'

// `require.resolve` and the keys of `require.cache` do not always agree. Under
// Bare the cache is keyed by file URL, and on Windows a resolved path uses
// backslashes while the cache key does not. Comparing them raw silently yields
// `undefined`, and the first property access on it then throws a TypeError far
// from the actual cause.
//
// The cache is passed in rather than read here so the caller's own `require`
// is always the one being inspected.

function normalize(value) {
  return value.replace(/\\/g, '/')
}

/** Resolve `path` to the key `cache` actually stores it under. */
function moduleCacheKey(cache, path) {
  if (cache[path] !== undefined) return path
  const target = normalize(path)
  const key = Object.keys(cache).find((candidate) => normalize(candidate).endsWith(target))
  if (key === undefined) throw new Error(`module cache entry not found: ${path}`)
  return key
}

module.exports = Object.freeze({ moduleCacheKey })
