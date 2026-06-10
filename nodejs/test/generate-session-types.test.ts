/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, expect, it } from "vitest";
import path from "path";

/**
 * Test suite for path traversal vulnerability mitigation in generate-session-types.ts
 * 
 * The security fix validates that schema paths cannot escape the base directory
 * using the following logic:
 * 
 * ```typescript
 * const base = path.resolve(__dirname);
 * const target = path.resolve(base, schemaPath);
 * const relative = path.relative(base, target);
 * if (relative.startsWith('..') || path.isAbsolute(relative)) {
 *     throw new Error('Invalid schema path');
 * }
 * ```
 * 
 * These tests verify that this validation correctly prevents path traversal attacks.
 */

/**
 * Helper function that mimics the path validation logic from generateCSharpTypes
 */
function validateSchemaPath(baseDir: string, schemaPath: string): boolean {
    const base = path.resolve(baseDir);
    const target = path.resolve(base, schemaPath);
    const relative = path.relative(base, target);
    
    // This is the security check from the actual code
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
        throw new Error('Invalid schema path');
    }
    
    return true;
}

describe("generate-session-types path traversal protection", () => {
    const baseDir = "/base/scripts";

    it("should reject path traversal with parent directory references (../)", () => {
        // Classic path traversal attempt
        const maliciousPath = "../../../etc/passwd";
        
        expect(() => {
            validateSchemaPath(baseDir, maliciousPath);
        }).toThrow("Invalid schema path");
    });

    it("should reject absolute paths", () => {
        // Absolute paths should be rejected to prevent access outside the base directory
        const absolutePath = "/etc/passwd";
        
        expect(() => {
            validateSchemaPath(baseDir, absolutePath);
        }).toThrow("Invalid schema path");
    });

    it("should reject paths that resolve outside the base directory", () => {
        // Path that appears to go into a subdirectory but then escapes
        const maliciousPath = "subdir/../../../../../../etc/passwd";
        
        expect(() => {
            validateSchemaPath(baseDir, maliciousPath);
        }).toThrow("Invalid schema path");
    });

    it("should accept valid relative paths within the base directory", () => {
        // Legitimate path within the base directory
        const validPath = "subdir/schema.json";
        
        expect(() => {
            validateSchemaPath(baseDir, validPath);
        }).not.toThrow();
    });

    it("should reject Windows-style absolute paths on Windows", () => {
        // Windows absolute path format
        // Note: On Unix systems, this is treated as a relative path with backslashes in the name
        // On Windows, path.isAbsolute() will correctly identify it as absolute
        const windowsAbsolutePath = "C:\\Windows\\System32\\config\\sam";
        
        // Only test on Windows or if the path is recognized as absolute
        if (process.platform === "win32" || path.isAbsolute(windowsAbsolutePath)) {
            expect(() => {
                validateSchemaPath(baseDir, windowsAbsolutePath);
            }).toThrow("Invalid schema path");
        } else {
            // On Unix, this is a relative path, so it should be accepted (though it's an odd filename)
            // The important thing is that it doesn't escape the base directory
            expect(() => {
                validateSchemaPath(baseDir, windowsAbsolutePath);
            }).not.toThrow();
        }
    });

    it("should reject mixed path separators with traversal", () => {
        // Mixed forward and backward slashes with traversal
        const mixedPath = "..\\..\\..\\etc/passwd";
        
        expect(() => {
            validateSchemaPath(baseDir, mixedPath);
        }).toThrow("Invalid schema path");
    });

    it("should reject path that escapes via symbolic link simulation", () => {
        // Path that tries to escape by going up multiple levels
        const maliciousPath = "a/b/c/../../../../../../../../etc/passwd";
        
        expect(() => {
            validateSchemaPath(baseDir, maliciousPath);
        }).toThrow("Invalid schema path");
    });

    it("should accept paths with dots in filenames", () => {
        // Ensure legitimate filenames with dots are not rejected
        const validPath = "schemas/session.events.schema.json";
        
        expect(() => {
            validateSchemaPath(baseDir, validPath);
        }).not.toThrow();
    });

    it("should accept current directory reference", () => {
        // Current directory reference should be allowed
        const validPath = "./schema.json";
        
        expect(() => {
            validateSchemaPath(baseDir, validPath);
        }).not.toThrow();
    });
});

describe("generate-session-types path validation logic", () => {
    it("should use path.relative to detect traversal attempts", () => {
        // This test documents the security mechanism used
        const base = path.resolve("/base/dir");
        
        // Test case 1: Path that escapes the base directory
        const maliciousTarget = path.resolve(base, "../../../etc/passwd");
        const maliciousRelative = path.relative(base, maliciousTarget);
        expect(maliciousRelative.startsWith("..") || path.isAbsolute(maliciousRelative)).toBe(true);
        
        // Test case 2: Safe path within the base directory
        const safeTarget = path.resolve(base, "subdir/file.json");
        const safeRelative = path.relative(base, safeTarget);
        expect(safeRelative.startsWith("..")).toBe(false);
        expect(path.isAbsolute(safeRelative)).toBe(false);
        
        // Test case 3: Absolute path
        const absoluteTarget = path.resolve("/etc/passwd");
        const absoluteRelative = path.relative(base, absoluteTarget);
        expect(absoluteRelative.startsWith("..") || path.isAbsolute(absoluteRelative)).toBe(true);
    });

    it("should normalize paths before validation", () => {
        // Verify that path.resolve normalizes paths correctly
        const base = path.resolve("/base/dir");
        
        // Path with redundant separators and dots
        const messyPath = "subdir/./file/../file.json";
        const target = path.resolve(base, messyPath);
        const relative = path.relative(base, target);
        
        // Should normalize to a clean relative path
        expect(relative).toBe(path.normalize("subdir/file.json"));
        expect(relative.startsWith("..")).toBe(false);
    });

    it("should handle edge case of base directory itself", () => {
        // Accessing the base directory itself should be allowed
        const base = path.resolve("/base/dir");
        const target = path.resolve(base, ".");
        const relative = path.relative(base, target);
        
        // Empty string or "." means same directory
        expect(relative).toBe("");
        expect(relative.startsWith("..")).toBe(false);
    });

    it("should detect traversal in complex nested paths", () => {
        // Complex path that eventually escapes
        const base = path.resolve("/base/dir");
        const maliciousTarget = path.resolve(base, "a/b/c/../../../../../../etc/passwd");
        const maliciousRelative = path.relative(base, maliciousTarget);
        
        // Should detect the escape
        expect(maliciousRelative.startsWith("..")).toBe(true);
    });
});

