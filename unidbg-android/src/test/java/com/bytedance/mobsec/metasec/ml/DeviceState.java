package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import java.io.File;
import java.io.IOException;

/**
 * What an install carries from one launch to the next: its second file.
 *
 * <p>The first file is the install's fingerprint ({@code fp_values_install.json}), generated once when the device is raised and
 * then never touched - the model's properties, and the settings this phone happens to have. This is the other half: the state
 * that keeps moving. Where the battery was when the app closed, how the phone was lying, when it was last opened, how many
 * events it has sent in its life, which video it last watched. Read at launch, advanced while the launch runs, written back at
 * the end.
 *
 * <p>Keeping it separate is the point. It used to live inside {@code identity.json}, which was doing three unrelated jobs at
 * once - identity that never changes (did, iid, keys), session credentials (cookies, sec_ts), and this evolving state - so
 * nothing said which values were supposed to move and the carry-forward happened by accident rather than by design. A request
 * that must agree with an earlier launch (a battery that has not jumped, a video this install actually saw) reads it from here.
 *
 * <p>An install opening for the first time has no ledger; every reader must cope with that rather than assume a value.
 */
class DeviceState {

    private final File file;
    private final JSONObject values;

    private DeviceState(File file, JSONObject values) {
        this.file = file;
        this.values = values;
    }

    /** this install's ledger, or an empty one when it has never been opened before */
    static DeviceState read(File file) throws IOException {
        if (file == null || !file.isFile()) {
            return new DeviceState(file, new JSONObject(true));
        }
        JSONObject parsed = JSON.parseObject(
                org.apache.commons.io.FileUtils.readFileToString(file, java.nio.charset.StandardCharsets.UTF_8));
        return new DeviceState(file, parsed == null ? new JSONObject(true) : parsed);
    }

    JSONObject values() {
        return values;
    }

    /** how long the phone sat with the app closed, in milliseconds, or -1 when this install has never been opened */
    long idleMillis(long nowWallClock) {
        Long last = values.getLong("last_opened_ms");
        return last == null ? -1 : Math.max(0, nowWallClock - last);
    }

    JSONObject section(String name) {
        return values.getJSONObject(name);
    }

    void put(String name, Object value) {
        values.put(name, value);
    }

    /**
     * The ledger as this launch leaves it. {@code last_opened_ms} is stamped here rather than by each caller, so the next
     * launch can always tell how long the phone was idle however this one ended.
     */
    void write(long nowWallClock) throws IOException {
        if (file == null) {
            return;
        }
        values.put("last_opened_ms", nowWallClock);
        values.put("_about", "what this install carries into its next launch (DeviceState): the state that keeps moving, "
                + "as opposed to its fingerprint in fp_values_install.json, which is generated once and then fixed. "
                + "device/dynamic.json documents what each entry means.");
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        org.apache.commons.io.FileUtils.writeStringToFile(file,
                JSON.toJSONString(values, com.alibaba.fastjson.serializer.SerializerFeature.PrettyFormat),
                java.nio.charset.StandardCharsets.UTF_8);
    }
}
