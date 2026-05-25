// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

enum SSHWildcardPatternMatcher {
    static func matches(_ value: String, pattern: String) -> Bool {
        let patternCharacters = Array(pattern)
        let valueCharacters = Array(value)

        var patternIndex = 0
        var valueIndex = 0
        var starPatternIndex: Int?
        var restartValueIndex = 0

        while valueIndex < valueCharacters.count {
            if patternIndex < patternCharacters.count,
               patternCharacters[patternIndex] == "*" {
                starPatternIndex = patternIndex
                patternIndex += 1
                restartValueIndex = valueIndex
                continue
            }

            if patternIndex < patternCharacters.count,
               (patternCharacters[patternIndex] == "?" ||
                patternCharacters[patternIndex] == valueCharacters[valueIndex]) {
                patternIndex += 1
                valueIndex += 1
                continue
            }

            if let starPatternIndex {
                patternIndex = starPatternIndex + 1
                restartValueIndex += 1
                valueIndex = restartValueIndex
                continue
            }

            return false
        }

        while patternIndex < patternCharacters.count,
              patternCharacters[patternIndex] == "*" {
            patternIndex += 1
        }

        return patternIndex == patternCharacters.count
    }
}
