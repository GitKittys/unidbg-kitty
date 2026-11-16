package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One device's recorded values: {@code device/fp_values_full.json}, exported by the user from a device run
 * ({@code scripts/export_full_values.py}). Sections: {@code f3a} (Java -> native f3.a calls), {@code msb} (MS.b callbacks, keyed by
 * cmd), {@code jni} (JNI calls metasec makes, keyed by {@code class.name(desc)ret} or {@code class.fieldDesc}) and {@code props}
 * (system properties; null = the device has no such property).
 * <p>
 * Value encoding: strings as is, boxed values {@code "Integer:5"}, long values {@code "0x.."}, byte[] {@code {cls:"[B",hex}},
 * primitive arrays {@code {cls:"[I",v:[..]}}, object arrays {@code {cls:"[L..;",v:[..]}}, other objects {@code {cls}} (a handle).
 */
final class DeviceProfile {

    private final JSONObject root;
    private final File file;

    DeviceProfile(File file) throws IOException {
        this.file = file.getAbsoluteFile();
        root = JSON.parseObject(FileUtils.readFileToString(file, StandardCharsets.UTF_8), Feature.OrderedField);
    }

    /** where side files named by the profile ({@code "file": "fs/..."}) are found: next to the profile */
    File dir() {
        return file.getParentFile();
    }

    /** a top-level section of the device description (sysinfo, network, uname, shell_commands...); null when the profile has none */
    Object section(String name) {
        return root.get(name);
    }

    /**
     * Every file the device's app sees that is this device's, by guest path: {@code text}/{@code hex} content, a side
     * {@code file}, a sparse file ({@code size} + {@code parts} offset -> side file), a {@code dir}, a {@code link}, an
     * {@code errno} the app gets instead (EACCES where SELinux denies it), and an optional {@code stat}. See
     * {@link MetasecStartup.ProfileFs}. Empty when the profile has no {@code fs}.
     */
    Map<String, JSONObject> fs() {
        Map<String, JSONObject> entries = new LinkedHashMap<>();
        JSONObject section = root.getJSONObject("fs");
        if (section != null) {
            for (Map.Entry<String, Object> entry : section.entrySet()) {
                entries.put(entry.getKey(), (JSONObject) entry.getValue());
            }
        }
        return entries;
    }

    /** the recorded f3.a calls with this cmd, in recorded order */
    List<JSONObject> f3a(int cmd) {
        return records("f3a", hex(cmd));
    }

    /** the recorded MS.b callbacks with this cmd */
    List<JSONObject> msb(int cmd) {
        return records("msb", hex(cmd));
    }

    /** the recorded JNI calls of this method or field */
    List<JSONObject> jni(String key) {
        return records("jni", key);
    }

    /**
     * Class -> a superclass, as the recording shows them: a call recorded under the method's class with a receiver of another class
     * (ClassLoader.loadClass on a PathClassLoader...)
     */
    Map<String, String> supertypes() {
        Map<String, String> supertypes = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : root.getJSONObject("jni").entrySet()) {
            String owner = entry.getKey().substring(0, entry.getKey().lastIndexOf('.'));
            for (Object record : (JSONArray) entry.getValue()) {
                Object self = ((JSONObject) record).get("self");
                if (self instanceof JSONObject) {
                    String cls = ((JSONObject) self).getString("cls");
                    if (cls != null && !cls.equals(owner)) {
                        supertypes.put(cls, owner);
                    }
                }
            }
        }
        return supertypes;
    }

    /** system properties in the order they were read; a null value = no such property */
    Map<String, String> properties() {
        Map<String, String> properties = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : root.getJSONObject("props").entrySet()) {
            properties.put(entry.getKey(), (String) entry.getValue());
        }
        return properties;
    }

    /**
     * A system property of the device: the ones metasec read ({@code props}), else the line {@code [name]: [value]} of the
     * {@code getprop} the device ran ({@code shell_commands}). Null when the profile has neither.
     */
    String getprop(String name) {
        Map<String, String> properties = properties();
        if (properties.get(name) != null) {
            return properties.get(name);
        }
        Object shell = section("shell_commands");
        if (shell instanceof JSONArray) {
            String key = "[" + name + "]: [";
            for (Object item : (JSONArray) shell) {
                JSONObject command = (JSONObject) item;
                if (!"getprop".equals(command.getString("cmd"))) {
                    continue;
                }
                JSONObject replay = command.getJSONObject("replay");
                String out = replay != null && replay.getString("stdout") != null ? replay.getString("stdout") : command.getString("stdout");
                int at = out == null ? -1 : out.indexOf(key);
                if (at >= 0) {
                    int end = out.indexOf(']', at + key.length());
                    return end < 0 ? null : out.substring(at + key.length(), end);
                }
            }
        }
        return null;
    }

    /**
     * metasec's own Keva values as the recording read them (repository {@link Build#kevaRepo()}): the sdi token, its counters, the
     * kd key. A null value = the key was absent; a key not listed is absent too (every key metasec read in the recording is here).
     */
    Map<String, String> kevaRead() {
        Map<String, String> values = new LinkedHashMap<>();
        JSONObject section = root.getJSONObject("keva_read");
        if (section != null) {
            for (Map.Entry<String, Object> entry : section.entrySet()) {
                values.put(entry.getKey(), entry.getValue() == null ? null : entry.getValue().toString());
            }
        }
        return values;
    }

    static String hex(int cmd) {
        return "0x" + Integer.toHexString(cmd);
    }

    /**
     * Values of a new install that exist only once the run has them: a profile of a first launch carries {@code {{did}}},
     * {@code {{iid}}}, {@code {{install_time}}} where the recording had its own, and the run puts the values here
     * ({@code device_register}'s answer, the install moment). Until then a token reads as empty, as the app's own fields are
     * before registration.
     */
    static final Map<String, String> INSTALL = new java.util.concurrent.ConcurrentHashMap<>();

    /** a profile string with the install's values in place of their tokens */
    static String resolve(String text) {
        if (text == null || !text.contains("{{")) {
            return text;
        }
        java.util.regex.Matcher token = java.util.regex.Pattern.compile("\\{\\{([a-z_0-9]+)\\}\\}").matcher(text);
        StringBuffer out = new StringBuffer();
        while (token.find()) {
            String value = INSTALL.get(token.group(1));
            token.appendReplacement(out, java.util.regex.Matcher.quoteReplacement(value == null ? "" : value));
        }
        token.appendTail(out);
        return out.toString();
    }

    /** whether the string names an install value the run does not have yet */
    static boolean pending(String text) {
        if (text == null || !text.contains("{{")) {
            return false;
        }
        java.util.regex.Matcher token = java.util.regex.Pattern.compile("\\{\\{([a-z_0-9]+)\\}\\}").matcher(text);
        while (token.find()) {
            if (!INSTALL.containsKey(token.group(1))) {
                return true;
            }
        }
        return false;
    }

    private List<JSONObject> records(String section, String key) {
        JSONArray array = root.getJSONObject(section).getJSONArray(key);
        return array == null ? Collections.<JSONObject>emptyList() : array.toJavaList(JSONObject.class);
    }

}
