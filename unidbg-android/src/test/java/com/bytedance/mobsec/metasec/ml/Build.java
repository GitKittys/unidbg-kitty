package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The constants of this build of {@code libmetasec_ml.so}: where it keeps the init state and the mask, which sign entries it
 * registers for either mask, the names of its Keva repositories and keys ({@code device/metasec.json}). They belong to the
 * library, not to the device: another build of the library is another file here.
 */
final class Build {

    /**
     * {@code example_binaries/metasec}, found whatever the working directory is.
     *
     * The examples used to name it relative to the repository root, so running them from a module directory (as an IDE
     * commonly does) failed to find the profile with nothing to say why. This walks up from the working directory until
     * it sees the resources, and {@code -Dmetasec.resources=<dir>} overrides it outright.
     */
    static final File RESOURCES = resources();

    private static File resources() {
        String override = System.getProperty("metasec.resources");
        if (override != null) {
            return new File(override);
        }
        String relative = "unidbg-android/src/test/resources/example_binaries/metasec";
        for (File dir = new File("").getAbsoluteFile(); dir != null; dir = dir.getParentFile()) {
            File candidate = new File(dir, relative);
            if (candidate.isDirectory()) {
                return candidate;
            }
            // already inside unidbg-android: the path below it is the tail of the one above
            File inModule = new File(dir, "src/test/resources/example_binaries/metasec");
            if (inModule.isDirectory()) {
                return inModule;
            }
        }
        throw new IllegalStateException("cannot find " + relative + " from " + new File("").getAbsolutePath()
                + " — run from the repository root, or pass -Dmetasec.resources=<dir>");
    }

    private final JSONObject json;

    Build(File file) throws IOException {
        json = JSON.parseObject(FileUtils.readFileToString(file, StandardCharsets.UTF_8));
    }

    String packageName() {
        return json.getString("package");
    }

    String library() {
        return json.getString("library");
    }

    /** the applog encryptor, loaded into the same emulator: {@code libEncryptor.so} */
    String encryptor() {
        return json.getString("encryptor");
    }

    /** a module-relative offset of a structure the sign reads */
    long offset(String name) {
        return Long.decode(json.getJSONObject("offsets").getString(name));
    }

    /** the sign entries the network library's setters receive: [http, ws], by bit 0x200 of the mask */
    long[] signEntries(boolean masked) {
        return entries(json.getJSONObject("sign_entries").getJSONArray(masked ? "masked" : "plain"));
    }

    long mask() {
        return offset("mask");
    }

    /** an offset inside the state block the context points at (seed, k, flags) */
    long state() {
        return Long.decode(json.getString("state"));
    }

    /** an offset inside a field slot {string object, refcount} */
    long slot(String name) {
        return Long.decode(json.getJSONObject("slots").getString(name));
    }

    /** an offset inside the instance's config object */
    long config(String name) {
        return Long.decode(json.getJSONObject("config").getString(name));
    }

    /** the environment variable the app sets before System.loadLibrary (d3.LIZIZ) */
    String[] environment() {
        return new String[]{json.getJSONObject("env").getString("name"), json.getJSONObject("env").getString("value")};
    }

    String kevaRepo() {
        return json.getJSONObject("keva").getString("repo");
    }

    /** "%s-%d-sdi": the appID and 0, the KV key of the sdi token */
    String sdiKey(String appId) {
        return appId + json.getJSONObject("keva").getString("sdi_key_suffix");
    }

    /** the KV key of the event counter X-Perseus reports as kd */
    String eventKey(String appId) {
        return appId + json.getJSONObject("keva").getString("event_key_suffix");
    }

    private static long[] entries(com.alibaba.fastjson.JSONArray array) {
        long[] values = new long[array.size()];
        for (int i = 0; i < values.length; i++) {
            values[i] = Long.decode(array.getString(i));
        }
        return values;
    }

}
