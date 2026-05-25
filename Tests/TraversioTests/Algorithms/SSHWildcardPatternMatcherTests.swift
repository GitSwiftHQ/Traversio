// Copyright (c) 2026 GitSwift LLC
//
// Licensed under the GNU Affero General Public License v3.0 or later.
// See LICENSE for details.

import Testing
@testable import Traversio

@Test(arguments: [
    ("", "*", true),
    ("aa", "a*", true),
    ("aa", "?a", true),
    ("ab", "*a", false),
    ("db.example.com", "*.example.com", true),
    ("db.example.net", "*.example.com", false),
])
func wildcardPatternMatcherMatchesOpenSSHPatternSemantics(
    value: String,
    pattern: String,
    expectedMatch: Bool
) {
    #expect(
        SSHWildcardPatternMatcher.matches(value, pattern: pattern)
            == expectedMatch
    )
}
