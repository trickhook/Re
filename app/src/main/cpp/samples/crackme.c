/*
 * crackme.c - a deliberately simple auth check, built as a small PIE executable
 * and bundled inside the Nocturne APK so its own debugger and analyzer have a
 * test target to load, breakpoint and defeat without importing anything.
 *
 * This is a standard reverse-engineering teaching artifact: the "secret" below
 * is a hard-coded constant in a toy program, not a credential to any real
 * system. Two legible patch points, named functions, real strings. See
 * docs/TEST-TARGET.md for the walkthrough.
 *
 * Built per ABI by the NDK (arm64-v8a, x86_64) via app/src/main/cpp/CMakeLists.txt
 * and landed at assets/samples/<abi>/crackme by app/build.gradle.kts, so
 * context.assets.open("samples/<abi>/crackme") finds it at runtime.
 */
#include <stdio.h>

/*
 * The value verify_key() compares against. Kept as a plain byte array so it
 * lands in .rodata and shows up in Nocturne's string panel, with an xref from
 * verify_key back to it.
 */
static const char SECRET[] = "NOCTURNE-2026";

/*
 * Patch point A.
 *
 * Returns 1 when key equals SECRET byte for byte (terminator included), else 0.
 * The per-byte compare-and-branch is what you breakpoint and watch: flip the
 * mismatch branch inside the loop (arm64 b.ne / b.eq, x86 jne / je) so every
 * byte "matches", or force the whole function to return 1.
 */
int verify_key(const char *key) {
    int i = 0;
    for (;;) {
        char expected = SECRET[i];
        char actual = key[i];
        if (actual != expected) {
            /* One byte differs: reject. This is the branch to flip. */
            return 0;
        }
        if (expected == '\0') {
            /* Both strings ended together with every byte equal: accept. */
            return 1;
        }
        i++;
    }
}

/*
 * Patch point B.
 *
 * Calls verify_key() and branches once on the result. Flip that branch (arm64
 * cbz / b.eq, x86 test+je) to take the GRANTED path regardless of the key.
 */
int main(int argc, char **argv) {
    const char *key = (argc > 1) ? argv[1] : "";

    printf("Nocturne crackme test target\n");
    printf("checking key: \"%s\"\n", key);

    if (verify_key(key)) {
        printf("ACCESS GRANTED\n");
        printf("flag{n0cturne_branch_flipped}\n");
        return 0;
    }

    printf("ACCESS DENIED\n");
    return 1;
}
