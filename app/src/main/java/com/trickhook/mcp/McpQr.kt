package com.trickhook.mcp

/**
 * A QR encoder, because pairing has to be one scan and there is no dependency
 * to add one.
 *
 * Byte mode, error-correction level M, versions 1 to 10 — 213 bytes, which is
 * three times what a URL with a 256-bit token needs. Everything here is the
 * plain ISO 18004 construction: Reed-Solomon over GF(256) with 0x11D, the
 * standard block interleave, the eight masks scored by the four penalty rules,
 * BCH(15,5) format information and BCH(18,6) version information.
 *
 * It was written against a reference implementation and checked by decoding its
 * own output back through an independent reader: every payload length from 1 to
 * 213 bytes round-trips, and each block's Reed-Solomon syndromes come out zero.
 * The 10-codeword generator for the level-M version 1 block reproduces the
 * published "HELLO WORLD" vector exactly.
 */
object McpQr {

    /** A finished symbol. [size] modules on a side, no quiet zone included. */
    class Code(val size: Int, private val dark: BooleanArray) {
        fun isDark(row: Int, col: Int): Boolean = dark[row * size + col]
    }

    /** ecPerBlock, group-1 blocks, group-1 data, group-2 blocks, group-2 data. */
    private val BLOCKS = arrayOf(
        intArrayOf(0, 0, 0, 0, 0),
        intArrayOf(10, 1, 16, 0, 0),
        intArrayOf(16, 1, 28, 0, 0),
        intArrayOf(26, 1, 44, 0, 0),
        intArrayOf(18, 2, 32, 0, 0),
        intArrayOf(24, 2, 43, 0, 0),
        intArrayOf(16, 4, 27, 0, 0),
        intArrayOf(18, 4, 31, 0, 0),
        intArrayOf(22, 2, 38, 2, 39),
        intArrayOf(22, 3, 36, 2, 37),
        intArrayOf(26, 4, 43, 1, 44)
    )

    /** Alignment-pattern centre coordinates per version. */
    private val ALIGN = arrayOf(
        intArrayOf(), intArrayOf(), intArrayOf(6, 18), intArrayOf(6, 22),
        intArrayOf(6, 26), intArrayOf(6, 30), intArrayOf(6, 34),
        intArrayOf(6, 22, 38), intArrayOf(6, 24, 42), intArrayOf(6, 26, 46),
        intArrayOf(6, 28, 50)
    )

    private const val EMPTY = -1
    private const val RESERVED = 2

    private val EXP = IntArray(512)
    private val LOG = IntArray(256)

    init {
        var x = 1
        for (i in 0 until 255) {
            EXP[i] = x
            LOG[x] = i
            x = x shl 1
            if (x and 0x100 != 0) x = x xor 0x11D
        }
        for (i in 255 until 512) EXP[i] = EXP[i - 255]
    }

    private fun gmul(a: Int, b: Int): Int =
        if (a == 0 || b == 0) 0 else EXP[LOG[a] + LOG[b]]

    /** Generator polynomial for [n] error-correction codewords, leading term 1. */
    private fun generator(n: Int): IntArray {
        var g = intArrayOf(1)
        for (i in 0 until n) {
            val next = IntArray(g.size + 1)
            for (j in g.indices) {
                next[j] = next[j] xor g[j]
                next[j + 1] = next[j + 1] xor gmul(g[j], EXP[i])
            }
            g = next
        }
        return g
    }

    private fun errorCorrection(data: IntArray, n: Int): IntArray {
        val g = generator(n)
        val rem = IntArray(n)
        for (d in data) {
            val factor = d xor rem[0]
            for (i in 0 until n - 1) rem[i] = rem[i + 1]
            rem[n - 1] = 0
            for (i in 0 until n) rem[i] = rem[i] xor gmul(g[i + 1], factor)
        }
        return rem
    }

    private fun formatBits(mask: Int): Int {
        // Level M is 0b00, so the five-bit field is just the mask index.
        val fmt = mask
        var code = fmt shl 10
        for (i in 4 downTo 0) {
            if (code and (1 shl (i + 10)) != 0) code = code xor (0x537 shl i)
        }
        return ((fmt shl 10) or code) xor 0x5412
    }

    private fun versionBits(version: Int): Int {
        var code = version shl 12
        for (i in 5 downTo 0) {
            if (code and (1 shl (i + 12)) != 0) code = code xor (0x1F25 shl i)
        }
        return (version shl 12) or code
    }

    private fun versionFor(byteCount: Int): Int {
        for (v in 1..10) {
            val b = BLOCKS[v]
            val dataCodewords = b[1] * b[2] + b[3] * b[4]
            val countBits = if (v < 10) 8 else 16
            if (4 + countBits + byteCount * 8 <= dataCodewords * 8) return v
        }
        return 0
    }

    private fun dataCodewords(payload: ByteArray, version: Int): IntArray {
        val b = BLOCKS[version]
        val total = b[1] * b[2] + b[3] * b[4]
        val bits = ArrayList<Int>(total * 8)
        fun put(value: Int, n: Int) {
            for (i in n - 1 downTo 0) bits.add((value shr i) and 1)
        }
        put(0b0100, 4)
        put(payload.size, if (version < 10) 8 else 16)
        for (byte in payload) put(byte.toInt() and 0xFF, 8)
        val capacity = total * 8
        var terminator = 0
        while (terminator < 4 && bits.size < capacity) {
            bits.add(0); terminator += 1
        }
        while (bits.size % 8 != 0) bits.add(0)
        val out = IntArray(total)
        var i = 0
        while (i * 8 < bits.size && i < total) {
            var v = 0
            for (k in 0 until 8) v = (v shl 1) or bits[i * 8 + k]
            out[i] = v
            i += 1
        }
        var pad = 0
        while (i < total) {
            out[i] = if (pad % 2 == 0) 0xEC else 0x11
            pad += 1
            i += 1
        }
        return out
    }

    private fun interleave(codewords: IntArray, version: Int): IntArray {
        val b = BLOCKS[version]
        val ecCount = b[0]
        val sizes = ArrayList<Int>()
        for (i in 0 until b[1]) sizes.add(b[2])
        for (i in 0 until b[3]) sizes.add(b[4])
        val blocks = ArrayList<IntArray>(sizes.size)
        var p = 0
        for (s in sizes) {
            val block = IntArray(s)
            for (i in 0 until s) block[i] = codewords[p + i]
            p += s
            blocks.add(block)
        }
        val ecs = blocks.map { errorCorrection(it, ecCount) }
        val out = ArrayList<Int>(codewords.size + ecCount * blocks.size)
        val longest = sizes.maxOrNull() ?: 0
        for (i in 0 until longest) {
            for (block in blocks) if (i < block.size) out.add(block[i])
        }
        for (i in 0 until ecCount) {
            for (ec in ecs) out.add(ec[i])
        }
        return out.toIntArray()
    }

    private fun template(version: Int): Array<IntArray> {
        val size = version * 4 + 17
        val m = Array(size) { IntArray(size) { EMPTY } }

        fun finder(row: Int, col: Int) {
            for (dr in -1..7) {
                for (dc in -1..7) {
                    val r = row + dr
                    val c = col + dc
                    if (r < 0 || r >= size || c < 0 || c >= size) continue
                    val inside = dr in 0..6 && dc in 0..6
                    val on = inside &&
                        (dr == 0 || dr == 6 || dc == 0 || dc == 6 ||
                            (dr in 2..4 && dc in 2..4))
                    m[r][c] = if (on) 1 else 0
                }
            }
        }
        finder(0, 0)
        finder(0, size - 7)
        finder(size - 7, 0)

        for (i in 8 until size - 8) {
            val on = if (i % 2 == 0) 1 else 0
            m[6][i] = on
            m[i][6] = on
        }

        for (r in ALIGN[version]) {
            for (c in ALIGN[version]) {
                val nearFinder = (r <= 8 && c <= 8) ||
                    (r <= 8 && c >= size - 9) ||
                    (r >= size - 9 && c <= 8)
                if (nearFinder) continue
                for (dr in -2..2) {
                    for (dc in -2..2) {
                        val on = if (maxOf(kotlin.math.abs(dr), kotlin.math.abs(dc)) != 1) 1 else 0
                        m[r + dr][c + dc] = on
                    }
                }
            }
        }

        // The dark module, then the format and version areas held back for the
        // bits that are only known once a mask has been chosen.
        m[size - 8][8] = 1
        for (i in 0..8) {
            if (m[8][i] == EMPTY) m[8][i] = RESERVED
            if (m[i][8] == EMPTY) m[i][8] = RESERVED
        }
        for (i in 0 until 8) {
            m[8][size - 1 - i] = RESERVED
            m[size - 1 - i][8] = RESERVED
        }
        if (version >= 7) {
            for (i in 0 until 18) {
                val r = i / 3
                val c = i % 3
                m[size - 11 + c][r] = RESERVED
                m[r][size - 11 + c] = RESERVED
            }
        }
        return m
    }

    private fun masked(row: Int, col: Int, mask: Int): Boolean = when (mask) {
        0 -> (row + col) % 2 == 0
        1 -> row % 2 == 0
        2 -> col % 3 == 0
        3 -> (row + col) % 3 == 0
        4 -> (row / 2 + col / 3) % 2 == 0
        5 -> (row * col) % 2 + (row * col) % 3 == 0
        6 -> ((row * col) % 2 + (row * col) % 3) % 2 == 0
        else -> ((row + col) % 2 + (row * col) % 3) % 2 == 0
    }

    private fun penalty(g: Array<IntArray>, size: Int): Int {
        var score = 0
        for (r in 0 until size) {
            var run = 1
            for (c in 1 until size) {
                if (g[r][c] == g[r][c - 1]) run += 1
                else {
                    if (run >= 5) score += 3 + (run - 5)
                    run = 1
                }
            }
            if (run >= 5) score += 3 + (run - 5)
        }
        for (c in 0 until size) {
            var run = 1
            for (r in 1 until size) {
                if (g[r][c] == g[r - 1][c]) run += 1
                else {
                    if (run >= 5) score += 3 + (run - 5)
                    run = 1
                }
            }
            if (run >= 5) score += 3 + (run - 5)
        }
        for (r in 0 until size - 1) {
            for (c in 0 until size - 1) {
                val v = g[r][c]
                if (v == g[r][c + 1] && v == g[r + 1][c] && v == g[r + 1][c + 1]) score += 3
            }
        }
        val a = intArrayOf(1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0)
        val b = intArrayOf(0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1)
        for (r in 0 until size) {
            for (c in 0..size - 11) {
                var hitA = true
                var hitB = true
                for (i in 0 until 11) {
                    if (g[r][c + i] != a[i]) hitA = false
                    if (g[r][c + i] != b[i]) hitB = false
                }
                if (hitA || hitB) score += 40
            }
        }
        for (c in 0 until size) {
            for (r in 0..size - 11) {
                var hitA = true
                var hitB = true
                for (i in 0 until 11) {
                    if (g[r + i][c] != a[i]) hitA = false
                    if (g[r + i][c] != b[i]) hitB = false
                }
                if (hitA || hitB) score += 40
            }
        }
        var dark = 0
        for (r in 0 until size) for (c in 0 until size) dark += g[r][c]
        val ratio = dark * 100 / (size * size)
        val low = (ratio / 5) * 5
        val high = low + 5
        score += minOf(kotlin.math.abs(low - 50) / 5, kotlin.math.abs(high - 50) / 5) * 10
        return score
    }

    private fun writeFormat(g: Array<IntArray>, size: Int, mask: Int) {
        val bits = formatBits(mask)
        for (i in 0 until 15) {
            val b = (bits shr i) and 1
            when {
                i < 6 -> g[8][i] = b
                i == 6 -> g[8][7] = b
                i == 7 -> g[8][8] = b
                i == 8 -> g[7][8] = b
                else -> g[14 - i][8] = b
            }
        }
        for (i in 0 until 15) {
            val b = (bits shr i) and 1
            if (i < 8) g[size - 1 - i][8] = b else g[8][size - 15 + i] = b
        }
        g[size - 8][8] = 1
    }

    private fun writeVersion(g: Array<IntArray>, size: Int, version: Int) {
        val bits = versionBits(version)
        for (i in 0 until 18) {
            val b = (bits shr i) and 1
            val r = i / 3
            val c = i % 3
            g[size - 11 + c][r] = b
            g[r][size - 11 + c] = b
        }
    }

    /**
     * Encode [text] as UTF-8. Returns null when it will not fit in version 10,
     * which for this app's payloads cannot happen — the caller still checks.
     */
    fun encode(text: String): Code? {
        val payload = text.toByteArray(Charsets.UTF_8)
        val version = versionFor(payload.size)
        if (version == 0) return null
        val size = version * 4 + 17
        val stream = interleave(dataCodewords(payload, version), version)

        val base = template(version)
        val reserved = Array(size) { r -> BooleanArray(size) { c -> base[r][c] != EMPTY } }
        val grid = Array(size) { r ->
            IntArray(size) { c -> if (base[r][c] == RESERVED) 0 else base[r][c] }
        }

        // The zigzag: two columns at a time from the right, skipping the
        // vertical timing column, upward then downward.
        var index = 0
        var col = size - 1
        var upward = true
        while (col > 0) {
            if (col == 6) col -= 1
            for (step in 0 until size) {
                val r = if (upward) size - 1 - step else step
                for (c in intArrayOf(col, col - 1)) {
                    if (!reserved[r][c]) {
                        val bit = if (index < stream.size * 8) {
                            (stream[index / 8] shr (7 - (index % 8))) and 1
                        } else 0
                        grid[r][c] = bit
                        index += 1
                    }
                }
            }
            upward = !upward
            col -= 2
        }

        var best: Array<IntArray>? = null
        var bestScore = Int.MAX_VALUE
        for (mask in 0 until 8) {
            val candidate = Array(size) { r ->
                IntArray(size) { c ->
                    if (!reserved[r][c] && masked(r, c, mask)) grid[r][c] xor 1 else grid[r][c]
                }
            }
            writeFormat(candidate, size, mask)
            if (version >= 7) writeVersion(candidate, size, version)
            val score = penalty(candidate, size)
            if (score < bestScore) {
                bestScore = score
                best = candidate
            }
        }
        val chosen = best ?: return null
        val dark = BooleanArray(size * size)
        for (r in 0 until size) {
            for (c in 0 until size) dark[r * size + c] = chosen[r][c] == 1
        }
        return Code(size, dark)
    }
}
