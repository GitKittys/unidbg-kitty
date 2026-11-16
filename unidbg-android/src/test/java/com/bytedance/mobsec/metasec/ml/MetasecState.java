package com.bytedance.mobsec.metasec.ml;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.io.File;
import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

/**
 * What metasec holds in memory that the sign reads (README_初始化流程 sections 4/5), read the way the user's scripts read it on the
 * device, and what its persisted state says it should hold. Offsets are this build's.
 */
class MetasecState {

    private final Emulator<?> emulator;
    private final long base;
    private final Build build;

    MetasecState(Emulator<?> emulator, long base, Build build) {
        this.emulator = emulator;
        this.base = base;
        this.build = build;
    }

    long seed() {
        return state().getInt(0) & 0xffffffffL;
    }

    long k() {
        return state().getInt(4) & 0xffffffffL;
    }

    long flags() {
        return state().getLong(8);
    }

    /** d350, d354, d358, d35C, d360 */
    long[] chain() {
        long[] chain = new long[5];
        for (int i = 0; i < chain.length; i++) {
            chain[i] = UnidbgPointer.pointer(emulator, base + build.offset("chain") + 4 * i).getInt(0) & 0xffffffffL;
        }
        return chain;
    }

    /** README 4: d350 = seed ^ k, d354 = bswap32, d358 = mix, d35C = sbox(rotl per flags bit 0/1), d360 = xorshift */
    long[] expectedChain() {
        long m = 0xffffffffL;
        long d350 = seed() ^ k();
        long d354 = Long.reverseBytes(d350 << 32) & m;
        long v = 2102535;
        for (int i = 0; i < 8; i++) {
            long b = (d354 >>> (8 * i)) & 0xff;
            v ^= (i & 1) != 0 ? (v >> 7) ^ ~(b | (v << 12)) : (v << 6) ^ (v >> 4) ^ b;
            v &= m;
        }
        long d358 = v;
        long v19 = d358;
        for (long bit = 1; bit <= 2; bit <<= 1) {
            if ((flags() & bit) != 0) {
                v19 = ((v19 << 1) | (v19 >>> 31)) & m;
            }
        }
        byte[] sbox = UnidbgPointer.pointer(emulator, base + build.offset("sbox")).getByteArray(0, 64);
        long d35c = 0;
        for (int i = 0; i < 4; i++) {
            d35c |= (long) (sbox[(int) ((v19 >>> (8 * i)) & 63)] & 0xff) << (8 * i);
        }
        long t = d35c ^ (d35c << 13);
        long w = ((t >> 17) ^ t) & m;
        long d360 = (w ^ (w << 5)) & m;
        return new long[]{d350, d354, d358, d35c, d360};
    }

    /** a field of the instance's config object (*(handle + 8)): +0x8 appID, +0x38 did, +0x48 iid, +0x58 session, +0xb0 SDK version */
    String config(long handle, String name) {
        long config = UnidbgPointer.pointer(emulator, handle + build.config("object")).getLong(0);
        return slot(config + build.config(name));
    }

    /** the session UUID metasec generated for this process (qword_57A990 -> string), null before it made one */
    String uuid() {
        long object = UnidbgPointer.pointer(emulator, base + build.offset("uuid")).getLong(0);
        return object == 0 ? null : slot(object);
    }

    /** the sdi token metasec holds, null before it has one */
    String sdiToken() {
        long object = UnidbgPointer.pointer(emulator, base + build.offset("sdi")).getLong(0);
        return object == 0 ? null : slot(object + build.slot("sdi_token"));
    }

    /** a field slot {string object, refcount}: the string's length at +0xc, its bytes at +0x10 */
    private String slot(long address) {
        long string = UnidbgPointer.pointer(emulator, address).getLong(0);
        if (string == 0) {
            return null;
        }
        int length = UnidbgPointer.pointer(emulator, string + build.slot("string_length")).getInt(0);
        long data = UnidbgPointer.pointer(emulator, string + build.slot("string_data")).getLong(0);
        return length == 0 ? "" : new String(UnidbgPointer.pointer(emulator, data).getByteArray(0, length), StandardCharsets.UTF_8);
    }

    private UnidbgPointer state() {
        long ctx = UnidbgPointer.pointer(emulator, base + build.offset("context")).getLong(0);
        long state = UnidbgPointer.pointer(emulator, UnidbgPointer.pointer(emulator, ctx).getLong(0) + build.state()).getLong(0);
        return UnidbgPointer.pointer(emulator, state);
    }

    /**
     * The sdi token a persisted multi-backend KV value holds (README 6b: hex(XXTEA(value, md5raw(key))) in Keva, the value
     * "crc32(token);token"), or null when it is absent or its crc does not match
     */
    static String persistedValue(String key, String hex) throws DecoderException {
        if (hex == null) {
            return null;
        }
        byte[] plain = xxteaDecrypt(Hex.decodeHex(hex.toCharArray()), DigestUtils.md5(key));
        return plain == null ? null : new String(plain, StandardCharsets.UTF_8);
    }

    static String persistedSdiToken(String key, String hex) throws DecoderException {
        if (hex == null) {
            return null;
        }
        byte[] plain = xxteaDecrypt(Hex.decodeHex(hex.toCharArray()), DigestUtils.md5(key));
        String value = plain == null ? null : new String(plain, StandardCharsets.UTF_8);
        int semicolon = value == null ? -1 : value.indexOf(';');
        if (semicolon == -1) {
            return null;
        }
        String token = value.substring(semicolon + 1);
        CRC32 crc = new CRC32();
        crc.update(token.getBytes(StandardCharsets.UTF_8));
        return String.valueOf(crc.getValue()).equals(value.substring(0, semicolon)) ? token : null;
    }

    /** metasec's XXTEA (scripts/ms_xxtea.py): the key a C string (cut at NUL, zero padded), the last word the plaintext length */
    private static byte[] xxteaDecrypt(byte[] data, byte[] key) {
        if (data.length < 8 || data.length % 4 != 0) {
            return null;
        }
        int nul = 0;
        while (nul < key.length && nul < 16 && key[nul] != 0) {
            nul++;
        }
        int[] k = new int[4];
        ByteBuffer.wrap(Arrays.copyOf(Arrays.copyOf(key, nul), 16)).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(k);
        int n = data.length / 4;
        int[] v = new int[n];
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(v);
        int delta = 0x9e3779b9;
        int sum = (6 + 52 / n) * delta, y = v[0];
        while (sum != 0) {
            int e = (sum >>> 2) & 3;
            for (int p = n - 1; p >= 0; p--) {
                int z = v[(p + n - 1) % n];
                v[p] -= (((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
                y = v[p];
            }
            sum -= delta;
        }
        int length = v[n - 1], max = 4 * (n - 1);
        if (length < max - 3 || length > max) {
            return null;
        }
        ByteBuffer bytes = ByteBuffer.allocate(4 * n).order(ByteOrder.LITTLE_ENDIAN);
        bytes.asIntBuffer().put(v);
        return Arrays.copyOf(bytes.array(), length);
    }

}

/**
 * ByteDance Keva repositories in an app's files/keva/repo (read from the files there; writes stay in memory).
 * <p>
 * Repository {@code <repo>} is the directory {@code <repo>} holding {@code <repo>.chk}, the index, and
 * {@code <repo>.blk}, the records. The records sit in three slabs of 64 slots (16 bytes at 0x30, 32 at 0x430, 64 at
 * 0xc30); a record is a u32 header (low 24 bits the length, high byte 0x81 a string) and its bytes, running into the next
 * slots when it is longer than its slot. The index is 8-byte entries from 0x128: a key ref (high byte 0x86; entries
 * with another one are not live) and a value ref (high byte 0x01, a string), whose low byte is class &lt;&lt; 6 | slot.
 * Other layouts throw; so does reading a value that is not a string.
 */
final class Keva {

    private static final int VERSION = 1;
    private static final int INDEX = 0x128;
    private static final int SLOTS = 64;
    private static final int[] SLAB = {0x30, 0x430, 0xc30};
    private static final int[] SLOT_SIZE = {16, 32, 64};
    /** u32s at 0x18 of a .chk */
    private static final int[] CHK_LAYOUT = {3, SLOTS, SLOTS, SLOTS};
    /** u32s at 0x10 of a .blk */
    private static final int[] BLK_LAYOUT = {0, SLOTS, SLOTS, 2, SLOTS, SLOTS, 16, 32};
    private static final int KEY_REF = 0x86;
    private static final int STRING_REF = 0x01;
    private static final int STRING_RECORD = 0x81;

    private final File repoDir;
    private final Map<String, Repo> repos = new HashMap<>();
    /** per repository, the keys put since; a null value is a removed key */
    private final Map<String, Map<String, String>> written = new HashMap<>();

    Keva(File repoDir) {
        this.repoDir = repoDir;
    }

    String get(String repo, String key) {
        Map<String, String> values = written.get(checkName(repo));
        if (values != null && values.containsKey(key)) {
            return values.get(key);
        }
        Repo loaded = repos.get(repo);
        if (loaded == null) {
            loaded = read(new File(repoDir, repo), repo);
            repos.put(repo, loaded);
        }
        String unsupported = loaded.unsupported.get(key);
        if (unsupported != null) {
            throw new IllegalStateException(unsupported);
        }
        return loaded.values.get(key);
    }

    void put(String repo, String key, String value) {
        Map<String, String> values = written.get(checkName(repo));
        if (values == null) {
            values = new HashMap<>();
            written.put(repo, values);
        }
        values.put(key, value);
    }

    private static String checkName(String repo) {
        if (repo.isEmpty() || ".".equals(repo) || "..".equals(repo) || repo.indexOf('/') >= 0 || repo.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("not a Keva repository name: " + repo);
        }
        return repo;
    }

    private static final class Repo {
        final Map<String, String> values = new HashMap<>();
        /** keys whose value is not a string, with why */
        final Map<String, String> unsupported = new HashMap<>();
    }

    private static Repo read(File dir, String name) {
        Repo repo = new Repo();
        File chkFile = new File(dir, name + ".chk");
        File blkFile = new File(dir, name + ".blk");
        if (!chkFile.exists() && !blkFile.exists()) {
            return repo;
        }
        ByteBuffer chk = load(chkFile, "keva-chk", 0x18, CHK_LAYOUT);
        ByteBuffer blk = load(blkFile, "keva-blk", 0x10, BLK_LAYOUT);
        int slabEnd = SLAB[2] + SLOTS * SLOT_SIZE[2];
        if (blk.capacity() < slabEnd) {
            throw new IllegalStateException(blkFile + ": " + blk.capacity() + " bytes, the slabs end at " + hex(slabEnd));
        }
        if (chk.capacity() < INDEX || (chk.capacity() - INDEX) % 8 != 0) {
            throw new IllegalStateException(chkFile + ": " + chk.capacity() + " bytes is not an index from " + hex(INDEX));
        }
        for (int off = 0x30; off < INDEX; off++) {
            if (chk.get(off) != 0) {
                throw new IllegalStateException(chkFile + ": unknown data at " + hex(off));
            }
        }
        boolean[][] used = new boolean[SLAB.length][SLOTS];
        for (int off = INDEX; off < chk.capacity(); off += 8) {
            int keyRef = chk.getInt(off);
            int valueRef = chk.getInt(off + 4);
            if (keyRef >>> 24 != KEY_REF) {
                continue;
            }
            String entry = chkFile + ": entry at " + hex(off);
            String key = record(blk, keyRef, used, entry + ", key");
            if (repo.values.containsKey(key) || repo.unsupported.containsKey(key)) {
                throw new IllegalStateException(entry + ": key '" + key + "' is in the index twice");
            }
            if (valueRef >>> 24 == STRING_REF) {
                repo.values.put(key, record(blk, valueRef, used, entry + ", value"));
            } else {
                repo.unsupported.put(key, entry + ": the value of '" + key + "' is not a string (ref " + hex(valueRef) + ")");
            }
        }
        return repo;
    }

    private static ByteBuffer load(File file, String magic, int layoutAt, int[] layout) {
        byte[] data;
        try {
            data = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new IllegalStateException("cannot read " + file, e);
        }
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (data.length < 0x30 || !magic.equals(new String(data, 0, 8, StandardCharsets.ISO_8859_1))) {
            throw new IllegalStateException(file + ": no " + magic + " magic at 0x0");
        }
        if (buffer.getInt(8) != VERSION) {
            throw new IllegalStateException(file + ": version " + buffer.getInt(8) + " at 0x8");
        }
        for (int i = 0; i < layout.length; i++) {
            int off = layoutAt + 4 * i;
            if (buffer.getInt(off) != layout[i]) {
                throw new IllegalStateException(file + ": unknown slab layout, " + hex(buffer.getInt(off)) + " at " + hex(off));
            }
        }
        return buffer;
    }

    /** the string record that ref points to, marking the slots it takes */
    private static String record(ByteBuffer blk, int ref, boolean[][] used, String what) {
        int cls = (ref & 0xff) >>> 6;
        int slot = ref & 0x3f;
        if ((ref & 0xffff00) != 0 || cls >= SLAB.length) {
            throw new IllegalStateException(what + ": unknown ref " + hex(ref));
        }
        int off = SLAB[cls] + slot * SLOT_SIZE[cls];
        int header = blk.getInt(off);
        int length = header & 0xffffff;
        String where = what + " record at " + hex(off) + " of the .blk";
        if (header >>> 24 != STRING_RECORD) {
            throw new IllegalStateException(where + ": header " + hex(header) + " is not a string");
        }
        int slots = (4 + length + SLOT_SIZE[cls] - 1) / SLOT_SIZE[cls];
        if (slot + slots > SLOTS) {
            throw new IllegalStateException(where + ": " + length + " bytes run past the end of its slab");
        }
        for (int i = slot; i < slot + slots; i++) {
            if (used[cls][i]) {
                throw new IllegalStateException(where + ": overlaps another record");
            }
            used[cls][i] = true;
        }
        byte[] bytes = new byte[length];
        ((ByteBuffer) blk.duplicate().position(off + 4)).get(bytes);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalStateException(where + ": not UTF-8", e);
        }
    }

    private static String hex(int value) {
        return "0x" + Integer.toHexString(value);
    }

}
