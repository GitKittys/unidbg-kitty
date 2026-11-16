package com.bytedance.mobsec.metasec.ml;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * One demo entry that shows what this fork of unidbg can bring up: a commercial Android hardening sample
 * (libmetasec_ml.so, "七神"/seven-gods) and its companion libraries run inside the emulator, and each of the
 * distinct native sign/report call sites is exercised from a single {@code main}.
 *
 * <p>This is a capability demonstration for the fork's {@code unicorn2} backend (EL0 boundary, virtual clock,
 * signal delivery, thread scheduling, filled syscalls). It brings the library up from a recorded,
 * <b>de-identified</b> device profile under {@code example_binaries/metasec/} — the fingerprint values there are
 * self-consistent placeholders, not a real device — and then calls each entry point:
 *
 * <ul>
 *   <li><b>http</b> — the HTTP request sign: metasec's seven headers
 *       (X-Argus / X-Gorgon / X-Helios / X-Khronos / X-Ladon / X-Medusa / X-Perseus),
 *       entered with a URL plus the request's header block ({@link MetasecEmulator#sign}).</li>
 *   <li><b>ws</b> — the WebSocket sign: a <i>different native call site at a different offset</i>
 *       ({@code ws_callback 0x5000001 → metasec+0x291324}, reached as {@code sscronet+0x396074 BLR X27} with a
 *       single kv-blob argument and no URL). It answers X-Cylons alone, 18 bytes of base64
 *       ({@link MetasecEmulator#signWs}).</li>
 *   <li><b>both</b> — signs the same input through the http entry and the ws entry side by side
 *       ({@link MetasecEmulator#signBothEntries}), to show the two call sites produce their own header sets.</li>
 *   <li><b>ttencrypt</b> — the applog / device_register body envelope: {@code EncryptorUtil.ttEncrypt} in
 *       libEncryptor.so, whose AES key/iv are fresh per call ({@link MetasecEmulator#ttEncrypt}).</li>
 *   <li><b>mssdk</b> — the mssdk report channel as recorded, a dry run by default
 *       (delegates to {@link MssdkUpload}; pass {@code --live} there to actually send).</li>
 * </ul>
 *
 * <p>Usage:
 * <pre>
 *   java ... MetasecDemo            # run every demo (http, ws, both, ttencrypt), mssdk as a dry run
 *   java ... MetasecDemo http       # just the seven-header HTTP sign
 *   java ... MetasecDemo ws         # just the WebSocket sign (the other call site)
 *   java ... MetasecDemo both       # the two sign entries side by side
 *   java ... MetasecDemo ttencrypt  # just the applog/device_register body envelope
 *   java ... MetasecDemo mssdk      # the mssdk report channel (dry run; add --live to send)
 * </pre>
 *
 * None of these needs a live network for the sign/encrypt demos — the signing happens entirely inside the
 * emulator. The mssdk demo only sends when explicitly asked.
 */
public final class MetasecDemo {

    /**
     * A realistically-shaped but de-identified request to sign. The URL and headers mirror the kind of request
     * the app signs (so metasec emits its full header set), with no account or session values: no cookie, no
     * install_id, no real device ids. The signer runs entirely inside the emulator and does not call out.
     */
    private static final String DEMO_URL =
            "https://api5-normal.amemv.com/service/settings/v2/?app=1&device_platform=android&version_code=390400&aid=1128";
    private static final String DEMO_HEADER_BLOB = String.join("\r\n",
            "sdk-version", "2",
            "x-ss-dp", "1128",
            "x-tt-request-tag", "s=0;p=0",
            "content-type", "application/x-www-form-urlencoded",
            "user-agent", "com.ss.android.ugc.aweme/390401 (Linux; U; Android 15; en; Build/demo)");
    /** a de-identified ws service/method kv blob (no URL on the ws entry) */
    private static final String DEMO_WS_BLOB = String.join("\r\n",
            "sdk-version", "2",
            "x-ss-dp", "1128");

    public static void main(String[] args) throws Exception {
        String which = args.length > 0 ? args[0].toLowerCase() : "all";
        boolean verbose = contains(args, "-v");

        switch (which) {
            case "http":
                try (MetasecEmulator ms = new MetasecEmulator(verbose)) {
                    http(ms);
                }
                break;
            case "ws":
                try (MetasecEmulator ms = new MetasecEmulator(verbose)) {
                    ws(ms);
                }
                break;
            case "both":
                try (MetasecEmulator ms = new MetasecEmulator(verbose)) {
                    both(ms);
                }
                break;
            case "ttencrypt":
                try (MetasecEmulator ms = new MetasecEmulator(verbose)) {
                    ttEncrypt(ms);
                }
                break;
            case "mssdk":
                // the mssdk report channel demo lives in MssdkUpload; forward the remaining args (e.g. --live)
                MssdkUpload.main(rest(args));
                break;
            case "all":
            default:
                try (MetasecEmulator ms = new MetasecEmulator(verbose)) {
                    http(ms);
                    System.out.println();
                    ws(ms);
                    System.out.println();
                    both(ms);
                    System.out.println();
                    ttEncrypt(ms);
                }
                System.out.println();
                System.out.println("== mssdk report channel (dry run; run `MetasecDemo mssdk --live` to send) ==");
                MssdkUpload.main(new String[0]);
                break;
        }
        System.exit(0);
    }

    /** the seven-header HTTP sign */
    private static void http(MetasecEmulator ms) {
        System.out.println("== http sign: the seven headers metasec produces for a request ==");
        System.out.println("   url = " + DEMO_URL);
        String block = ms.sign(DEMO_URL, DEMO_HEADER_BLOB);
        printBlock(block);
    }

    /** the WebSocket sign: the other native call site (X-Cylons alone) */
    private static void ws(MetasecEmulator ms) {
        System.out.println("== ws sign: the WebSocket call site (ws_callback 0x5000001 -> metasec+0x291324), X-Cylons alone ==");
        System.out.println("   blob = " + DEMO_WS_BLOB.replace("\r\n", " | "));
        String block = ms.signWs(DEMO_WS_BLOB);
        printBlock(block);
    }

    /** both entries side by side, to show the offsets/call sites differ */
    private static void both(MetasecEmulator ms) {
        System.out.println("== both entries, same input through the http call site and the ws call site ==");
        String[][] entries = ms.signBothEntries(DEMO_URL, DEMO_HEADER_BLOB);
        String[] names = {"http entry", "ws entry"};
        for (int i = 0; i < entries.length; i++) {
            System.out.println("   " + (i < names.length ? names[i] : ("entry " + i)) + ":");
            String[] kv = entries[i];
            for (int j = 0; j + 1 < kv.length; j += 2) {
                System.out.printf("     %-12s %s%n", kv[j], abbreviate(kv[j + 1]));
            }
        }
    }

    /** the applog / device_register body envelope */
    private static void ttEncrypt(MetasecEmulator ms) {
        System.out.println("== ttEncrypt: the applog / device_register body envelope (fresh AES key/iv per call) ==");
        byte[] plaintext = "{\"demo\":\"body\"}".getBytes(StandardCharsets.UTF_8);
        byte[] out = ms.ttEncrypt(plaintext);
        if (out == null) {
            System.out.println("   ttEncrypt returned null");
            return;
        }
        System.out.printf("   %d bytes in -> %d bytes out%n", plaintext.length, out.length);
        System.out.println("   key = " + hex(ms.key()));
        System.out.println("   iv  = " + hex(ms.iv()));
        System.out.println("   out = " + hex(out));
    }

    private static void printBlock(String block) {
        if (block == null) {
            System.out.println("   the signer returned null");
            return;
        }
        String[] lines = block.split("\r\n", -1);
        for (int i = 0; i + 1 < lines.length; i += 2) {
            System.out.printf("   %-12s %4d chars  %s%n", lines[i], lines[i + 1].length(), abbreviate(lines[i + 1]));
        }
    }

    private static String abbreviate(String s) {
        if (s == null) {
            return "(null)";
        }
        return s.length() <= 72 ? s : s.substring(0, 69) + "...";
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte value : b) {
            sb.append(Character.forDigit((value >> 4) & 0xf, 16)).append(Character.forDigit(value & 0xf, 16));
        }
        return sb.toString();
    }

    private static boolean contains(String[] args, String flag) {
        for (String a : args) {
            if (flag.equals(a)) {
                return true;
            }
        }
        return false;
    }

    /** args without the leading subcommand, so a subcommand can forward the rest (e.g. mssdk --live) */
    private static String[] rest(String[] args) {
        if (args.length <= 1) {
            return new String[0];
        }
        String[] out = new String[args.length - 1];
        System.arraycopy(args, 1, out, 0, out.length);
        return out;
    }

    private MetasecDemo() {
    }
}
