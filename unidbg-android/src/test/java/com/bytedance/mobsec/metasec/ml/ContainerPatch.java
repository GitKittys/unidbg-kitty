package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.io.FileUtils;
import unicorn.Arm64Const;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Feeds the mssdk containers the fields this environment does not collect (no shell, no network interface, no display density...)
 * with the device's own values, at the place metasec serialises them: the container message is recognised when metasec's
 * protobuf init returns it, and just before the pack call every configured field is written into the struct by its descriptor
 * offset ({@code device/mssdk_descs.json}).
 * <p>
 * Data: {@code device/mssdk_patch.json} — container descriptor offset -> path ("/#2/#32", a string in sub-message #2) -> value.
 * This is the "patch what is missing" way unidbg is used: metasec still does its own work, only the values it could not obtain here
 * come from the recording.
 */
final class ContainerPatch {

    private final Emulator<?> emulator;
    private final long base;
    private final JSONObject descriptors;
    private final JSONObject containers;
    private final int[] debug = new int[1];
    private final Map<Long, String> messages = new java.util.concurrent.ConcurrentHashMap<>(); // struct pointer -> container descriptor

    ContainerPatch(Emulator<?> emulator, long base, File descriptors, File patch) throws IOException {
        this.emulator = emulator;
        this.base = base;
        this.descriptors = JSON.parseObject(FileUtils.readFileToString(descriptors, StandardCharsets.UTF_8));
        this.containers = JSON.parseObject(FileUtils.readFileToString(patch, StandardCharsets.UTF_8)).getJSONObject("containers");
    }

    /**
     * Hook the pack call. A protobuf-c message carries its descriptor pointer first, so the container is recognised from the
     * struct itself: descriptor address - module base = the offset the data file is keyed by.
     */
    /** string values are allocated once, before emulation starts: allocation is not possible from inside a hook */
    private void prepareStrings() {
        for (Map.Entry<String, Object> container : containers.entrySet()) {
            JSONObject descriptor = descriptors.getJSONObject(container.getKey());
            for (Map.Entry<String, Object> entry : ((JSONObject) container.getValue()).entrySet()) {
                if (typeOf(descriptor, entry.getKey()).endsWith("string")) {
                    if (entry.getValue() instanceof com.alibaba.fastjson.JSONArray) {
                        com.alibaba.fastjson.JSONArray items = (com.alibaba.fastjson.JSONArray) entry.getValue();
                        MemoryBlock pointers = emulator.getMemory().malloc(items.size() * 8, false);
                        for (int i = 0; i < items.size(); i++) {
                            byte[] text = String.valueOf(items.getString(i)).getBytes(StandardCharsets.UTF_8);
                            MemoryBlock block = emulator.getMemory().malloc(text.length + 1, false);
                            block.getPointer().write(0, text, 0, text.length);
                            block.getPointer().setByte(text.length, (byte) 0);
                            pointers.getPointer().setLong(i * 8, block.getPointer().peer);
                        }
                        allocated.put(container.getKey() + entry.getKey(), pointers.getPointer().peer);
                    } else {
                        byte[] text = String.valueOf(entry.getValue()).getBytes(StandardCharsets.UTF_8);
                        MemoryBlock block = emulator.getMemory().malloc(text.length + 1, false);
                        block.getPointer().write(0, text, 0, text.length);
                        block.getPointer().setByte(text.length, (byte) 0);
                        allocated.put(container.getKey() + entry.getKey(), block.getPointer().peer);
                    }
                }
            }
        }
    }

    private final Map<String, Long> allocated = new HashMap<>();

    /** the field's descriptor type for a path, "" when it cannot be resolved */
    private String typeOf(JSONObject descriptor, String path) {
        String[] segments = path.split("/");
        for (int i = 1; i < segments.length; i++) {
            JSONObject field = field(descriptor, Integer.parseInt(segments[i].substring(1)));
            if (field == null) {
                return "";
            }
            if (i == segments.length - 1) {
                return field.getString("type");
            }
            descriptor = descriptors.getJSONObject(field.getString("sub"));
            if (descriptor == null) {
                return "";
            }
        }
        return "";
    }

    void install(long packOffset) {
        prepareStrings();
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long message = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                if (message < 0x10000) {
                    return;
                }
                long descriptor;
                try {
                    descriptor = UnidbgPointer.pointer(emulator, message).getLong(0);
                } catch (RuntimeException e) {
                    return;
                }
                if (descriptor < base) {
                    return;
                }
                String container = "0x" + Long.toHexString(descriptor - base);
                if (Boolean.getBoolean("metasec.patchDebug") && debug[0]++ < 12) {
                    System.out.printf("  [patch] pack msg=0x%x desc=0x%x -> +0x%x%n", message, descriptor, descriptor - base);
                }
                if (containers.containsKey(container)) {
                    patch(message, container);
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, base + packOffset, base + packOffset, null);
    }

    private void patch(long message, String container) {
        JSONObject paths = containers.getJSONObject(container);
        if (paths == null) {
            return;
        }
        JSONObject descriptor = descriptors.getJSONObject(container);
        int written = 0;
        for (Map.Entry<String, Object> entry : paths.entrySet()) {
            try {
                if (write(message, descriptor, entry.getKey(), entry.getValue(), container)) {
                    written++;
                } else if (Boolean.getBoolean("metasec.patchDebug")) {
                    System.out.println("  [patch] skipped " + entry.getKey());
                }
            } catch (RuntimeException e) {
                System.out.println("  [patch] " + entry.getKey() + ": " + e);
            }
        }
        if (Boolean.getBoolean("metasec.patchDebug") || written > 0) {
            System.out.printf("  [patch] %s: %d/%d fields written%n", container, written, paths.size());
        }
    }

    /** one "/#2/#32" path: walk sub-messages, then write the value at the field's offset */
    private boolean write(long message, JSONObject descriptor, String path, Object value, String container) {
        String[] segments = path.split("/");
        long address = message;
        for (int i = 1; i < segments.length; i++) {
            int id = Integer.parseInt(segments[i].substring(1));
            JSONObject field = field(descriptor, id);
            if (field == null) {
                return false;
            }
            int offset = field.getIntValue("off");
            boolean last = i == segments.length - 1;
            if (!last) {
                if (!"message".equals(field.getString("type"))) {
                    return false;
                }
                address = UnidbgPointer.pointer(emulator, address + offset).getLong(0);
                if (address == 0) {
                    return false; // the container has no such sub-message in this build state
                }
                descriptor = descriptors.getJSONObject(field.getString("sub"));
                if (descriptor == null) {
                    return false;
                }
                // a sub-message carries its own descriptor pointer first: refuse to write if it is another message type
                long expected = base + Long.decode(field.getString("sub"));
                long actual = UnidbgPointer.pointer(emulator, address).getLong(0);
                if (actual != expected) {
                    if (Boolean.getBoolean("metasec.patchDebug")) {
                        System.out.printf("  [patch] %s: sub-message descriptor 0x%x != 0x%x, skipped%n", path, actual, expected);
                    }
                    return false;
                }
                continue;
            }
            String type = field.getString("type");
            if ("REPEATED".equals(field.getString("label"))) {
                return writeRepeated(message, address, offset, type, value, container + path);
            }
            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address + offset);
            switch (type) {
                case "string": {
                    Long text = allocated.get(container + path);
                    if (text == null) {
                        return false;
                    }
                    pointer.setLong(0, text);
                    return true;
                }
                case "int64":
                case "uint64":
                    pointer.setLong(0, Long.parseLong(String.valueOf(value)));
                    return true;
                case "sint64": {
                    // protobuf-c zigzags a sint field on the wire; the recorded value is already decoded, so store its inverse
                    long plain = Long.parseLong(String.valueOf(value));
                    pointer.setLong(0, (plain >>> 1) ^ -(plain & 1));
                    return true;
                }
                case "sint32": {
                    int plain = (int) Long.parseLong(String.valueOf(value));
                    pointer.setInt(0, (plain >>> 1) ^ -(plain & 1));
                    return true;
                }
                case "int32":
                case "uint32":
                case "fixed32":
                case "sfixed32":
                case "enum":
                    pointer.setInt(0, (int) Long.parseLong(String.valueOf(value)));
                    return true;
                case "bool":
                    pointer.setInt(0, Boolean.parseBoolean(String.valueOf(value)) ? 1 : 0);
                    return true;
                case "double":
                    pointer.setDouble(0, Double.parseDouble(String.valueOf(value)));
                    return true;
                case "float":
                    pointer.setFloat(0, Float.parseFloat(String.valueOf(value)));
                    return true;
                default:
                    return false; // bytes/repeated: left to the device's own producer
            }
        }
        return false;
    }

    /**
     * protobuf-c keeps a repeated string as { size_t n; char **items; }: the count lives right before the pointer the descriptor
     * points at. The array and its strings are allocated before emulation (see prepareStrings).
     */
    private boolean writeRepeated(long message, long address, int offset, String type, Object value, String key) {
        if (!"string".equals(type) || !(value instanceof com.alibaba.fastjson.JSONArray)) {
            return false;
        }
        Long array = allocated.get(key);
        if (array == null) {
            return false;
        }
        UnidbgPointer.pointer(emulator, address + offset - 8).setLong(0, ((com.alibaba.fastjson.JSONArray) value).size());
        UnidbgPointer.pointer(emulator, address + offset).setLong(0, array);
        return true;
    }

    private static JSONObject field(JSONObject descriptor, int id) {
        for (Object item : descriptor.getJSONArray("fields")) {
            JSONObject field = (JSONObject) item;
            if (field.getIntValue("id") == id) {
                return field;
            }
        }
        return null;
    }

}
