package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.linux.android.ElfLibraryFile;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.LibraryFile;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

/**
 * What is assembled once, when the emulated device starts, and nothing else: the system property area written into the rootfs,
 * the two IOResolvers (recorded stat, /proc/self) and the library resolver. They are used from
 * {@link MetasecSign#run(boolean, boolean)} only, so they live together here instead of in four files of their own.
 */
final class MetasecStartup {

    private MetasecStartup() {
    }

    /**
     * The system property area Android 6 bionic maps from {@code /dev/__properties__}: a prop_area header, then a trie of
     * prop_bt nodes (one binary search tree per '.'-separated level) and prop_info records, laid out the way init's
     * {@code __system_property_add} lays them out when it adds the same properties in the same order.
     * Properties bionic's own writer refuses are rejected. The file is PA_SIZE (128 KiB) long, or whole multiples of it when
     * the properties do not fit (libc maps the file's st_size).
     */
    static final class PropertyArea {


        private static final int PA_SIZE = 128 * 1024;
        private static final int HEADER_SIZE = 128;
        private static final int PROP_AREA_MAGIC = 0x504f5250;
        private static final int PROP_AREA_VERSION = 0xfc6ed0ab;
        private static final int PROP_NAME_MAX = 32;
        private static final int PROP_VALUE_MAX = 92;

        private static final int BT_PROP = 4;
        private static final int BT_LEFT = 8;
        private static final int BT_RIGHT = 12;
        private static final int BT_CHILDREN = 16;
        private static final int BT_NAME = 20;
        private static final int INFO_VALUE = 4;
        private static final int INFO_NAME = INFO_VALUE + PROP_VALUE_MAX;

        /**
         * @param properties name to value, added in iteration order (a LinkedHashMap keeps the insertion order);
         *                   a null value means there is no such property
         * @return the contents of /dev/__properties__
         */
        static byte[] build(Map<String, String> properties) {
            PropertyArea area = new PropertyArea();
            for (Map.Entry<String, String> entry : properties.entrySet()) {
                if (entry.getValue() != null) {
                    area.add(entry.getKey(), entry.getValue());
                }
            }
            return area.toByteArray();
        }

        private byte[] data = new byte[PA_SIZE - HEADER_SIZE];
        private int bytesUsed = BT_NAME; // the root prop_bt
        private int serial;

        private PropertyArea() {
        }

        private void add(String key, String value) {
            byte[] name = key.getBytes(StandardCharsets.UTF_8);
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            if (name.length < 1 || name.length >= PROP_NAME_MAX || indexOf(name, (byte) 0, 0) != -1) {
                throw new IllegalArgumentException("property name must be 1-" + (PROP_NAME_MAX - 1) + " bytes without NUL: " + key);
            }
            if (bytes.length >= PROP_VALUE_MAX || indexOf(bytes, (byte) 0, 0) != -1) {
                throw new IllegalArgumentException("value of " + key + " must be shorter than " + PROP_VALUE_MAX + " bytes without NUL: " + value);
            }

            int current = 0;
            int start = 0;
            while (true) {
                int sep = indexOf(name, (byte) '.', start);
                int end = sep == -1 ? name.length : sep;
                if (end == start) {
                    throw new IllegalArgumentException("empty name segment: " + key);
                }
                current = findPropBt(current + BT_CHILDREN, name, start, end - start);
                if (sep == -1) {
                    break;
                }
                start = sep + 1;
            }
            if (getInt(current + BT_PROP) != 0) {
                throw new IllegalArgumentException("duplicate property: " + key);
            }
            int info = allocate(INFO_NAME + name.length + 1);
            putInt(info, bytes.length << 24);
            System.arraycopy(bytes, 0, data, info + INFO_VALUE, bytes.length);
            System.arraycopy(name, 0, data, info + INFO_NAME, name.length);
            putInt(current + BT_PROP, info);
            serial++;
        }

        /**
         * Walks the tree whose root offset is stored at {@code link}, adding the node where the search ends if it is missing.
         */
        private int findPropBt(int link, byte[] name, int off, int len) {
            while (true) {
                int current = getInt(link);
                if (current == 0) {
                    current = allocate(BT_NAME + len + 1);
                    data[current] = (byte) len;
                    System.arraycopy(name, off, data, current + BT_NAME, len);
                    putInt(link, current);
                    return current;
                }
                int ret = compare(name, off, len, current);
                if (ret == 0) {
                    return current;
                }
                link = current + (ret < 0 ? BT_LEFT : BT_RIGHT);
            }
        }

        /**
         * cmp_prop_name: shorter names first, then strncmp.
         */
        private int compare(byte[] name, int off, int len, int bt) {
            int btLen = data[bt] & 0xff;
            if (len != btLen) {
                return len < btLen ? -1 : 1;
            }
            for (int i = 0; i < len; i++) {
                int diff = (name[off + i] & 0xff) - (data[bt + BT_NAME + i] & 0xff);
                if (diff != 0) {
                    return diff;
                }
            }
            return 0;
        }

        private int allocate(int size) {
            int off = bytesUsed;
            bytesUsed += (size + 3) & ~3;
            if (bytesUsed > data.length) {
                data = Arrays.copyOf(data, data.length + PA_SIZE);
            }
            return off;
        }

        private byte[] toByteArray() {
            int size = (HEADER_SIZE + bytesUsed + PA_SIZE - 1) / PA_SIZE * PA_SIZE;
            byte[] area = new byte[size];
            putInt(area, 0, bytesUsed);
            putInt(area, 4, serial);
            putInt(area, 8, PROP_AREA_MAGIC);
            putInt(area, 12, PROP_AREA_VERSION);
            System.arraycopy(data, 0, area, HEADER_SIZE, bytesUsed);
            return area;
        }

        private int getInt(int off) {
            return (data[off] & 0xff) | (data[off + 1] & 0xff) << 8 | (data[off + 2] & 0xff) << 16 | (data[off + 3] & 0xff) << 24;
        }

        private void putInt(int off, int value) {
            putInt(data, off, value);
        }

        private static void putInt(byte[] buf, int off, int value) {
            buf[off] = (byte) value;
            buf[off + 1] = (byte) (value >>> 8);
            buf[off + 2] = (byte) (value >>> 16);
            buf[off + 3] = (byte) (value >>> 24);
        }

        private static int indexOf(byte[] bytes, byte b, int from) {
            for (int i = from; i < bytes.length; i++) {
                if (bytes[i] == b) {
                    return i;
                }
            }
            return -1;
        }
    }

    /**
     * The process environment, seen by every reader of it. unidbg keeps two: the array it built ({@code ANDROID_DATA},
     * {@code ANDROID_ROOT}, an old {@code PATH}, {@code NO_ADDR_COMPAT_LAYOUT_FIXUP}), which its dlsym hands to every {@code environ}
     * import, and libc's own {@code environ}, which libc's setenv/getenv use; a setenv never reached the import (metasec lists the
     * environment through it and reported "!notset!"). Here the environment starts as {@code inherited} (what an app process gets
     * from zygote; unidbg's array when the profile has none), the variables are set through libc's setenv in order, and the
     * import is pointed at the result.
     */
    /**
     * sysconf(_SC_NPROCESSORS_ONLN / _CONF) as the device's libc answers it: Android 15's bionic reads
     * /sys/devices/system/cpu/online (possible), unidbg's Android 6 libc counts the cpu lines of /proc/stat, which an app may not
     * read on the device (EACCES in the profile), so it said 1 where the device says 9. The count comes from the profile's files.
     */
    static void cpuCount(final Emulator<?> emulator, com.github.unidbg.Module libc, Map<String, JSONObject> fs) {
        final int online = cpus(fs.get("/sys/devices/system/cpu/online")), possible = cpus(fs.get("/sys/devices/system/cpu/possible"));
        com.github.unidbg.Symbol sysconf = libc.findSymbolByName("sysconf", false);
        if (sysconf == null || online <= 0) {
            return;
        }
        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                long name = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                if (name == 97 || name == 96) { // _SC_NPROCESSORS_ONLN, _SC_NPROCESSORS_CONF
                    backend.reg_write(unicorn.Arm64Const.UC_ARM64_REG_X0, name == 97 || possible <= 0 ? online : possible);
                    backend.reg_write(unicorn.Arm64Const.UC_ARM64_REG_PC, backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue());
                }
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, sysconf.getAddress(), sysconf.getAddress(), null);
    }

    /** the number of CPUs in a kernel cpu list ("0-8", "0,2-3") */
    private static int cpus(JSONObject file) {
        if (file == null || file.getString("text") == null) {
            return 0;
        }
        int count = 0;
        for (String part : file.getString("text").trim().split(",")) {
            String[] range = part.split("-");
            count += range.length == 2 ? Integer.parseInt(range[1].trim()) - Integer.parseInt(range[0].trim()) + 1 : 1;
        }
        return count;
    }

    static void environment(Emulator<?> emulator, com.github.unidbg.Module libc, List<String> inherited, List<String[]> variables) {
        com.github.unidbg.memory.Memory memory = emulator.getMemory();
        com.github.unidbg.Symbol symbol = memory.dlsym(0, "environ");
        com.github.unidbg.Symbol own = libc.findSymbolByName("environ", false);
        UnidbgPointer slot = symbol == null ? null : UnidbgPointer.pointer(emulator, symbol.getAddress());
        UnidbgPointer variable = own == null ? null : UnidbgPointer.pointer(emulator, own.getAddress());
        if (slot != null && !inherited.isEmpty()) {
            com.github.unidbg.memory.MemoryBlock array = memory.malloc((inherited.size() + 1) * 8, false);
            for (int i = 0; i < inherited.size(); i++) {
                byte[] text = inherited.get(i).getBytes(StandardCharsets.UTF_8);
                com.github.unidbg.memory.MemoryBlock entry = memory.malloc(text.length + 1, false);
                entry.getPointer().write(0, Arrays.copyOf(text, text.length + 1), 0, text.length + 1);
                array.getPointer().setPointer(i * 8L, entry.getPointer());
            }
            array.getPointer().setPointer(inherited.size() * 8L, null);
            slot.setPointer(0, array.getPointer());
        }
        if (slot != null && variable != null) {
            variable.setPointer(0, slot.getPointer(0)); // one environment: libc starts from it
        }
        for (String[] entry : variables) {
            libc.callFunction(emulator, "setenv", entry[0], entry[1], 1);
        }
        if (slot != null && variable != null) {
            slot.setPointer(0, variable.getPointer(0)); // and the environ import sees what setenv made
        }
    }

    /**
     * The device's files, from the profile's {@code fs} section (one entry per guest path), so a device is described by its JSON
     * and the rootfs stays a system skeleton:
     * <ul>
     *   <li>{@code text} / {@code hex} / {@code file} (a side file next to the profile): written into the run's root, then served by
     *       unidbg like any rootfs file (reads, mmap, writes by the guest);</li>
     *   <li>{@code size} + {@code parts} (offset -> side file): a sparse file of the real size holding only the recorded ranges
     *       (the APK: metasec reads 4.5 MB of the 349 MB, the rest stays zero);</li>
     *   <li>{@code dir}: a directory; with {@code list} (names in the device's getdents order, a directory with a trailing
     *       {@code /}) it lists exactly those, and with {@code stat} it reports the recorded fields (unidbg reports a directory as
     *       mode S_IFDIR with no permissions, inode 0, times 0). {@code /data/data/<pkg>} reaches the {@code /data/user/0/<pkg>}
     *       entry, as the bind mount does;</li>
     *   <li>{@code link}: a symlink; opening it opens the target, {@link #link} answers readlink;</li>
     *   <li>{@code errno}: what the app gets instead of the file (13 = EACCES, where SELinux denies an app what root could read);</li>
     *   <li>{@code stat}: st_mode/st_uid/st_gid/st_dev/st_ino/st_atime/st_mtime/st_ctime reported instead of the host file's. A recording
     *       that only knows {@code st_dev+st_ino} (the sum ends up in a persisted value) leaves st_dev as unidbg reports it.</li>
     * </ul>
     */
    static final class ProfileFs implements IOResolver<AndroidFileIO> {

        private final Map<String, JSONObject> entries;
        private final File[] sideDirs;
        private File rootDir;

        /**
         * sideDirs: where the side files a profile names ({@code "file": "fs/..."}) are looked for, in order — the profile's own
         * directory first, then the bundled device directory, so a copied and edited profile still finds the shared libraries
         */
        ProfileFs(Map<String, JSONObject> entries, File... sideDirs) {
            this.entries = entries;
            this.sideDirs = sideDirs;
        }

        private File side(String name) {
            for (File dir : sideDirs) {
                File file = new File(dir, name);
                if (file.isFile()) {
                    return file;
                }
            }
            throw new IllegalStateException("fs: side file " + name + " is in none of " + Arrays.toString(sideDirs));
        }

        /** writes the content and directory entries into the run's root; errno and link entries stay virtual */
        void materialize(File rootDir) throws IOException {
            this.rootDir = rootDir;
            for (Map.Entry<String, JSONObject> entry : entries.entrySet()) {
                JSONObject e = entry.getValue();
                if (e.containsKey("errno") || e.containsKey("link")) {
                    continue;
                }
                File file = new File(rootDir, entry.getKey().substring(1));
                if (e.getBooleanValue("dir")) {
                    FileUtils.forceMkdir(file);
                    com.alibaba.fastjson.JSONArray list = e.getJSONArray("list");
                    for (int i = 0; list != null && i < list.size(); i++) {
                        String name = list.getString(i);
                        if (name.endsWith("/") && name.indexOf(':') < 0) { // a name the host cannot hold is listed, not created
                            FileUtils.forceMkdir(new File(file, name.substring(0, name.length() - 1)));
                        }
                    }
                } else if (e.containsKey("parts") && complete(e) != null) {
                    // -Dmetasec.apk=<the same APK in full>: what the recording kept of it are parts; a library that reads further
                    // (badger's signature block check) needs the rest. Used only when every recorded part matches it
                    FileUtils.copyFile(complete(e), file, false);
                    file.setWritable(true); // unidbg opens files read-write
                } else if (e.containsKey("parts")) {
                    FileUtils.forceMkdirParent(file);
                    try (java.io.RandomAccessFile out = new java.io.RandomAccessFile(file, "rw")) {
                        out.setLength(e.getLongValue("size"));
                        for (Map.Entry<String, Object> part : e.getJSONObject("parts").entrySet()) {
                            out.seek(Long.parseLong(part.getKey()));
                            out.write(FileUtils.readFileToByteArray(side((String) part.getValue())));
                        }
                    }
                } else if (e.containsKey("file")) {
                    FileUtils.copyFile(side(e.getString("file")), file);
                } else if (e.containsKey("hex")) {
                    FileUtils.writeByteArrayToFile(file, hex(e.getString("hex")));
                } else {
                    FileUtils.writeStringToFile(file, e.getString("text"), StandardCharsets.UTF_8);
                }
            }
        }

        /** the full file -Dmetasec.apk names when this sparse entry is that file (same size, every recorded part equal), else null */
        private File complete(JSONObject e) throws IOException {
            String path = System.getProperty("metasec.apk");
            if (path == null || path.isEmpty()) {
                return null;
            }
            File full = new File(path);
            if (!full.isFile() || full.length() != e.getLongValue("size")) {
                return null;
            }
            try (java.io.RandomAccessFile in = new java.io.RandomAccessFile(full, "r")) {
                for (Map.Entry<String, Object> part : e.getJSONObject("parts").entrySet()) {
                    byte[] recorded = FileUtils.readFileToByteArray(side((String) part.getValue()));
                    byte[] actual = new byte[recorded.length];
                    in.seek(Long.parseLong(part.getKey()));
                    in.readFully(actual);
                    if (!java.util.Arrays.equals(recorded, actual)) {
                        return null;
                    }
                }
            }
            return full;
        }

        /** the target when the profile has this path as a symlink, else null */
        String link(String pathname) {
            JSONObject e = entries.get(pathname);
            return e == null ? null : e.getString("link");
        }

        /** the errno the app gets for this path, else 0 */
        int errno(String pathname) {
            JSONObject e = entries.get(pathname);
            return e == null ? 0 : e.getIntValue("errno");
        }

        @Override
        public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
            JSONObject found = pathname == null ? null : entries.get(pathname);
            String local = pathname;
            if (found == null && pathname != null && pathname.length() > 1 && pathname.endsWith("/")) {
                JSONObject directory = entries.get(pathname.substring(0, pathname.length() - 1)); // "dir/" is the directory
                if (directory != null && directory.getBooleanValue("dir")) {
                    found = directory;
                    local = pathname.substring(0, pathname.length() - 1);
                }
            }
            if (found == null && pathname != null && pathname.startsWith("/data/data/")) {
                JSONObject alias = entries.get("/data/user/0/" + pathname.substring("/data/data/".length()));
                if (alias != null && alias.getBooleanValue("dir")) {
                    found = alias; // the same directory (bind mount); the files under it stay with DataDataAlias
                    local = "/data/user/0/" + pathname.substring("/data/data/".length());
                }
            }
            final JSONObject e = found;
            if (e == null || rootDir == null) {
                return null;
            }
            if (e.getBooleanValue("dir") && (e.containsKey("list") || e.containsKey("stat"))) {
                return FileResult.<AndroidFileIO>success(new DeviceDirectory(oflags, pathname, new File(rootDir, local.substring(1)), e));
            }
            if (e.containsKey("errno")) {
                return FileResult.failed(e.getIntValue("errno"));
            }
            JSONObject target = e;
            File file = new File(rootDir, pathname.substring(1));
            if (e.containsKey("link")) {
                String to = e.getString("link");
                if (!to.startsWith("/")) {
                    to = pathname.substring(0, pathname.lastIndexOf('/') + 1) + to; // a relative target, as /proc/mounts -> self/mounts
                }
                file = new File(rootDir, to.substring(1));
                target = entries.containsKey(to) ? entries.get(to) : new JSONObject();
            }
            if (!file.isFile()) {
                return null; // a directory (unidbg lists it from the root) or a link whose target the profile does not have
            }
            return FileResult.<AndroidFileIO>success(new DeviceFileIO(oflags, file, pathname, target));
        }

        /**
         * A profile file as the kernel serves it. stat reports the recorded fields; ioctl answers what the profile records for the
         * request ({@code "ioctl": {"0x...": "<hex written to argp>"}}) and otherwise fails like the kernel: ENOTTY for a regular
         * file, or the entry's {@code ioctl_errno} (a device's EINVAL). unidbg's own file IO throws on any ioctl, which ends the
         * guest thread that asked.
         */
        private static final class DeviceFileIO extends SimpleFileIO {

            private final JSONObject stat;
            private final JSONObject ioctl;
            private final int ioctlErrno;

            DeviceFileIO(int oflags, File file, String path, JSONObject entry) {
                super(oflags, file, path);
                this.stat = entry.getJSONObject("stat");
                this.ioctl = entry.getJSONObject("ioctl");
                this.ioctlErrno = entry.containsKey("ioctl_errno") ? entry.getIntValue("ioctl_errno") : 25; // ENOTTY
            }

            @Override
            public int fstat(Emulator<?> emulator, StatStructure st) {
                int ret = super.fstat(emulator, st);
                return stat == null ? ret : recorded(stat, st);
            }

            @Override
            public int ioctl(Emulator<?> emulator, long request, long argp) {
                String reply = ioctl == null ? null : ioctl.getString("0x" + Long.toHexString(request & 0xffffffffL));
                if (reply == null) {
                    return -ioctlErrno;
                }
                byte[] bytes = hex(reply);
                if (bytes.length > 0) {
                    UnidbgPointer.pointer(emulator, argp).write(0, bytes, 0, bytes.length);
                }
                return 0;
            }
        }

        /** a directory of the profile: its recorded listing and stat */
        private static final class DeviceDirectory extends DirectoryFileIO {

            private final JSONObject stat;

            DeviceDirectory(int oflags, String path, File dir, JSONObject entry) {
                super(oflags, path, entries(dir, entry));
                this.stat = entry.getJSONObject("stat");
            }

            private static DirectoryEntry[] entries(File dir, JSONObject entry) {
                com.alibaba.fastjson.JSONArray list = entry.getJSONArray("list");
                List<DirectoryEntry> entries = new ArrayList<>();
                if (list == null) {
                    File[] files = dir.listFiles();
                    for (File file : files == null ? new File[0] : files) {
                        entries.add(new DirectoryEntry(file.isFile(), file.getName()));
                    }
                } else {
                    for (int i = 0; i < list.size(); i++) {
                        String name = list.getString(i);
                        boolean directory = name.endsWith("/");
                        entries.add(new DirectoryEntry(!directory, directory ? name.substring(0, name.length() - 1) : name));
                    }
                }
                return entries.toArray(new DirectoryEntry[0]);
            }

            @Override
            public int fstat(Emulator<?> emulator, StatStructure st) {
                int ret = super.fstat(emulator, st);
                return stat == null ? ret : recorded(stat, st);
            }
        }

        /** the recorded stat fields over what unidbg filled in */
        private static int recorded(JSONObject stat, StatStructure st) {
            {
                if (stat.containsKey("st_mode")) {
                    st.st_mode = stat.getIntValue("st_mode");
                }
                if (stat.containsKey("st_uid")) {
                    st.st_uid = stat.getIntValue("st_uid");
                    st.st_gid = stat.getIntValue("st_gid");
                }
                if (stat.containsKey("st_dev")) {
                    st.st_dev = stat.getLongValue("st_dev");
                    st.setSt_ino(stat.getLongValue("st_ino"));
                } else if (stat.containsKey("st_dev+st_ino")) {
                    st.setSt_ino(stat.getLongValue("st_dev+st_ino") - st.st_dev);
                }
                if (stat.containsKey("st_mtime")) {
                    st.setSt_atim(stat.getLongValue("st_atime") * 1000, 0);
                    st.setSt_mtim(stat.getLongValue("st_mtime") * 1000, 0);
                    st.setSt_ctim(stat.getLongValue("st_ctime") * 1000, 0);
                }
                if (stat.containsKey("st_nlink")) {
                    st.st_nlink = stat.getIntValue("st_nlink");
                }
                if (stat.containsKey("st_size")) {
                    st.st_size = stat.getLongValue("st_size");
                }
                st.pack();
                return 0;
            }
        }

        private static byte[] hex(String text) {
            try {
                return org.apache.commons.codec.binary.Hex.decodeHex(text.toCharArray());
            } catch (org.apache.commons.codec.DecoderException e) {
                throw new IllegalArgumentException("fs: not hex", e);
            }
        }
    }

    /**
     * The process files metasec reads ({@code /proc/self/status}, {@code cmdline}, {@code stat}, {@code cgroup}, {@code mounts}) from
     * the device's own copy of them, kept in the rootfs under {@code proc/self/}: the guest's pid is not the device's, so the
     * {@code /proc/<pid>/...} spelling reaches the same file.
     */
    static final class ProcSelf implements IOResolver<AndroidFileIO> {


        private static final Set<String> FILES = new HashSet<>(Arrays.asList("status", "cmdline", "stat", "cgroup", "mounts", "mountinfo"));

        private final File rootDir;

        ProcSelf(File rootDir) {
            this.rootDir = rootDir;
        }

        @Override
        public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
            String[] parts = pathname.split("/");
            if (parts.length != 4 || !"proc".equals(parts[1]) || !FILES.contains(parts[3])) {
                return null;
            }
            if (!"self".equals(parts[2]) && !parts[2].equals(String.valueOf(emulator.getPid()))) {
                return null;
            }
            File file = new File(rootDir, "proc/self/" + parts[3]);
            return file.isFile() ? FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, file, pathname)) : null;
        }
    }

    /**
     * The process as the device shows it, rendered at the moment it is read from the profile's {@code process} section:
     * {@code /proc/self/status}, {@code /proc/self/stat} and {@code /proc/self/task/<tid>/{status,stat,comm}} (also under
     * {@code /proc/<pid>/}). A copy of the recorded files would be another process (pid 7750 and its thread ids); here the pid is
     * the emulator's and the threads are its own (main = pid, the guest's pthreads with the names it gave them), plus the app's
     * other threads as the device had them while metasec initialised (offsets from the pid, names, states, signal masks):
     * pid-bearing names re-rendered ({@code binder:{pid}_1}), context-switch counters moved a little per run, Threads: the count
     * listed, and the thread that reads shown running. On the device metasec's own threads scan these names continuously
     * (~100k task comm opens a session).
     */
    static final class ProcessView implements IOResolver<AndroidFileIO> {

        private static final java.util.regex.Pattern PATH = java.util.regex.Pattern.compile(
                "^/proc/(self|\\d+)(?:/(status|stat)|/task(?:/(\\d+)(?:/(status|stat|comm))?)?/?)$");

        private final Emulator<?> emulator;
        private final MetasecSyscalls syscalls;
        private final String status;
        private final String stat;
        private final String comm;
        private final List<JSONObject> others = new ArrayList<>();
        /** the device's metasec workers (ART-attached Thread-N) in creation order: who the guest's pthreads are */
        private final List<JSONObject> guests = new ArrayList<>();
        /** the thread that loaded metasec on the device: a worker that never attaches to ART keeps its creator's name */
        private final String initThread;

        ProcessView(JSONObject process, Emulator<?> emulator, MetasecSyscalls syscalls) {
            this.emulator = emulator;
            this.syscalls = syscalls;
            this.status = process.getString("status");
            this.stat = process.getString("stat");
            this.comm = field(status, "Name");
            for (Object thread : process.getJSONArray("threads")) {
                others.add((JSONObject) thread);
            }
            if (process.containsKey("guest_threads")) {
                for (Object thread : process.getJSONArray("guest_threads")) {
                    guests.add((JSONObject) thread);
                }
            }
            this.initThread = process.containsKey("init_thread") ? process.getString("init_thread") : comm;
        }

        /** diagnostic (-Dmetasec.dumpProcess=dir): the task list and the files of the main thread and two others, as rendered */
        void dump(File dir) throws IOException {
            java.util.TreeMap<Integer, Thread> threads = threads();
            StringBuilder list = new StringBuilder();
            for (Map.Entry<Integer, Thread> entry : threads.entrySet()) {
                list.append(entry.getKey()).append('\t').append(entry.getValue().name).append('\n');
            }
            FileUtils.writeStringToFile(new File(dir, "task_comm.txt"), list.toString(), StandardCharsets.UTF_8);
            int pid = emulator.getPid();
            List<Integer> tids = new ArrayList<>(threads.keySet());
            for (int tid : new int[]{pid, tids.get(Math.min(5, tids.size() - 1)), tids.get(tids.size() - 1)}) {
                for (String file : new String[]{"status", "stat", "comm"}) {
                    FileUtils.writeStringToFile(new File(dir, tid + "_" + file + ".txt"),
                            render(file, tid, threads.get(tid), threads.size()), StandardCharsets.UTF_8);
                }
            }
        }

        /** the process name: the main thread's comm */
        String comm() {
            return comm;
        }

        private static final class Thread {
            final String name, state, sigblk;
            final long vctx, nvctx;

            Thread(String name, String state, String sigblk, long vctx, long nvctx) {
                this.name = name;
                this.state = state;
                this.sigblk = sigblk;
                this.vctx = vctx;
                this.nvctx = nvctx;
            }
        }

        /** tid -> thread in tid order: the main thread, the emulator's threads, then the app's other threads on free tids */
        private java.util.TreeMap<Integer, Thread> threads() {
            int pid = emulator.getPid();
            java.util.TreeMap<Integer, Thread> threads = new java.util.TreeMap<>();
            threads.put(pid, new Thread(comm, field(status, "State"), field(status, "SigBlk"),
                    jitter(pid, pid, Long.parseLong(field(status, "voluntary_ctxt_switches"))),
                    jitter(pid, -pid, Long.parseLong(field(status, "nonvoluntary_ctxt_switches")))));
            List<Integer> workers = new ArrayList<>();
            for (com.github.unidbg.thread.Task task : emulator.getThreadDispatcher().getTaskList()) {
                if (task.getId() != pid) {
                    workers.add(task.getId());
                }
            }
            java.util.Collections.sort(workers); // unidbg hands out tids in creation order
            for (int i = 0; i < workers.size(); i++) {
                int tid = workers.get(i);
                JSONObject guest = i < guests.size() ? guests.get(i) : null;
                String named = syscalls.threadName(tid);
                String name = named != null ? named : guest != null ? guest.getString("name") : initThread;
                threads.put(tid, guest == null
                        ? new Thread(name, "S (sleeping)", "0000000080001204", jitter(pid, tid, 8), jitter(pid, -tid, 2))
                        : new Thread(name, guest.getString("state"), guest.getString("sigblk"),
                        jitter(pid, tid, guest.getLongValue("vctx")), jitter(pid, -tid, guest.getLongValue("nvctx"))));
            }
            for (JSONObject other : others) {
                int tid = pid + other.getIntValue("offset");
                while (threads.containsKey(tid)) {
                    tid++;
                }
                threads.put(tid, new Thread(other.getString("name").replace("{pid}", String.valueOf(pid)),
                        other.getString("state"), other.getString("sigblk"),
                        jitter(pid, tid, other.getLongValue("vctx")), jitter(pid, -tid, other.getLongValue("nvctx"))));
            }
            return threads;
        }

        /** a counter as this run reads it: the device's value moved by up to a tenth, the same for the same pid and tid */
        private static long jitter(int pid, int tid, long value) {
            java.util.Random random = new java.util.Random(pid * 1000003L + tid);
            return value + random.nextInt((int) Math.min(Integer.MAX_VALUE, value / 10 + 2));
        }

        @Override
        public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
            java.util.regex.Matcher m = pathname == null ? null : PATH.matcher(pathname);
            if (m == null || !m.matches()) {
                return null;
            }
            int pid = emulator.getPid();
            if (!"self".equals(m.group(1)) && Integer.parseInt(m.group(1)) != pid) {
                return null; // another process
            }
            java.util.TreeMap<Integer, Thread> threads = threads();
            if (m.group(2) != null) {
                return file(oflags, pathname, render(m.group(2), pid, threads.get(pid), threads.size()));
            }
            if (m.group(3) == null) {
                List<DirectoryFileIO.DirectoryEntry> entries = new ArrayList<>();
                for (Integer tid : threads.keySet()) {
                    entries.add(new DirectoryFileIO.DirectoryEntry(false, String.valueOf(tid)));
                }
                return FileResult.<AndroidFileIO>success(new DirectoryFileIO(oflags, pathname,
                        entries.toArray(new DirectoryFileIO.DirectoryEntry[0])));
            }
            int tid = Integer.parseInt(m.group(3));
            Thread thread = threads.get(tid);
            if (thread == null) {
                return FileResult.failed(com.github.unidbg.unix.UnixEmulator.ENOENT);
            }
            if (m.group(4) == null) {
                return FileResult.<AndroidFileIO>success(new DirectoryFileIO(oflags, pathname,
                        new DirectoryFileIO.DirectoryEntry(true, "comm"),
                        new DirectoryFileIO.DirectoryEntry(true, "stat"),
                        new DirectoryFileIO.DirectoryEntry(true, "status")));
            }
            return file(oflags, pathname, render(m.group(4), tid, thread, threads.size()));
        }

        private String render(String file, int tid, Thread thread, int count) {
            com.github.unidbg.thread.Task current = emulator.get(com.github.unidbg.thread.Task.TASK_KEY);
            int reader = current == null ? emulator.getPid() : current.getId();
            String state = tid == reader ? "R (running)" : thread.state;
            if ("comm".equals(file)) {
                return thread.name + "\n";
            }
            if ("status".equals(file)) {
                StringBuilder out = new StringBuilder();
                String[] lines = status.split("\n", -1);
                for (int i = 0; i < lines.length; i++) {
                    String line = lines[i];
                    int colon = line.indexOf(':');
                    String key = colon < 0 ? "" : line.substring(0, colon);
                    switch (key) {
                        case "Name": line = "Name:\t" + thread.name; break;
                        case "State": line = "State:\t" + state; break;
                        case "Tgid": line = "Tgid:\t" + emulator.getPid(); break;
                        case "Pid": line = "Pid:\t" + tid; break;
                        case "Threads": line = "Threads:\t" + count; break;
                        case "SigBlk": line = "SigBlk:\t" + thread.sigblk; break;
                        case "voluntary_ctxt_switches": line = "voluntary_ctxt_switches:\t" + thread.vctx; break;
                        case "nonvoluntary_ctxt_switches": line = "nonvoluntary_ctxt_switches:\t" + thread.nvctx; break;
                        default: break;
                    }
                    out.append(line);
                    if (i < lines.length - 1) {
                        out.append('\n');
                    }
                }
                return out.toString();
            }
            // stat: "pid (comm) S ppid ...": the fields after the comm are the main thread's, num_threads (field 20) the count
            String rest = stat.substring(stat.lastIndexOf(')') + 2);
            String[] fields = rest.split(" ", -1);
            fields[0] = state.substring(0, 1);
            fields[17] = String.valueOf(count);
            return tid + " (" + thread.name + ") " + String.join(" ", fields);
        }

        private static FileResult<AndroidFileIO> file(int oflags, String pathname, String text) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, text.getBytes(StandardCharsets.UTF_8)));
        }

        private static String field(String status, String key) {
            for (String line : status.split("\n")) {
                if (line.startsWith(key + ":")) {
                    return line.substring(key.length() + 1).trim();
                }
            }
            throw new IllegalArgumentException("process.status has no " + key);
        }
    }

    /**
     * {@code /proc/self/maps} (and {@code /proc/<pid>/maps}). Starts from what unidbg generates for the emulated memory (its
     * modules, the stack, the other mappings) — the addresses metasec dereferences must stay those — and lets the run add to it:
     * {@code -Dmetasec.mapsExtra=<file>} appends lines (an experiment: does metasec's output react to what maps lists?),
     * {@code -Dmetasec.dumpMaps=<file>} writes the text the guest read. Without either the content is unidbg's own.
     */
    static final class MapsView implements IOResolver<AndroidFileIO> {

        private final String extra;
        private final File dump;
        /** lines for guest mappings the harness made in place of the device's file mappings, by unidbg's "start-end " prefix */
        private final Map<String, String> named = new java.util.LinkedHashMap<>();

        MapsView(String extra, File dump) {
            this.extra = extra;
            this.dump = dump;
        }

        /**
         * The profile's {@code mapped_files}: a file mapping the device process has and unidbg does not make (ART maps part of
         * base.apk, r--s). The same bytes go into a guest mapping of their own, and maps lists it under the file's name, offset,
         * device and inode (the file's recorded stat), as the device's line does
         */
        void mapFiles(Emulator<?> emulator, JSONObject section, Map<String, JSONObject> fs, File rootDir) throws IOException {
            for (Object item : section.getJSONArray("list")) {
                JSONObject file = (JSONObject) item;
                String path = file.getString("path");
                int length = file.getIntValue("length");
                long offset = file.getLongValue("offset");
                byte[] bytes = new byte[length];
                File host = new File(rootDir, path.substring(1));
                if (host.isFile()) {
                    try (java.io.RandomAccessFile in = new java.io.RandomAccessFile(host, "r")) {
                        in.seek(offset);
                        in.readFully(bytes);
                    }
                }
                com.github.unidbg.pointer.UnidbgPointer mapping = emulator.getMemory().mmap(length, unicorn.UnicornConst.UC_PROT_READ
                        | unicorn.UnicornConst.UC_PROT_WRITE);
                mapping.write(0, bytes, 0, length);
                long start = mapping.peer;
                emulator.getMemory().mprotect(start, length, unicorn.UnicornConst.UC_PROT_READ);
                JSONObject stat = fs.get(path) == null ? null : fs.get(path).getJSONObject("stat");
                long dev = stat == null ? 0 : stat.getLongValue("st_dev"), ino = stat == null ? 0 : stat.getLongValue("st_ino");
                named.put(String.format("%08x-%08x ", start, start + length), String.format("%08x-%08x %s %08x %02x:%02x %d", start,
                        start + length, file.getString("perms"), offset, (dev >> 8) & 0xfff, dev & 0xff, ino) + "                        " + path + "\n");
            }
        }

        boolean active() {
            return extra != null || dump != null || !named.isEmpty();
        }

        /** unidbg's generator, which is protected */
        private static final class Unidbg extends com.github.unidbg.linux.file.MapsFileIO {
            private Unidbg() {
                super(0, null, new byte[0]);
            }

            static byte[] data(Emulator<?> emulator) {
                return getMapsData(emulator, emulator.getMemory().getLoadedModules(), null);
            }
        }

        @Override
        public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
            if (!"/proc/self/maps".equals(pathname) && !("/proc/" + emulator.getPid() + "/maps").equals(pathname)) {
                return null;
            }
            String text = new String(Unidbg.data(emulator), StandardCharsets.UTF_8);
            if (!named.isEmpty()) {
                StringBuilder lines = new StringBuilder();
                for (String line : text.split("\n")) {
                    String prefix = line.length() > 18 ? line.substring(0, line.indexOf(' ') + 1) : line;
                    lines.append(named.containsKey(prefix) ? named.get(prefix) : line + "\n");
                }
                text = lines.toString();
            }
            if (extra != null) {
                text = text + extra;
            }
            if (dump != null) {
                try {
                    FileUtils.writeStringToFile(dump, text, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, text.getBytes(StandardCharsets.UTF_8)));
        }
    }

    /**
     * JNI ids the way ART hands them out. On the device a jmethodID is an {@code ArtMethod*} and a jfieldID an {@code ArtField*}:
     * addresses in the class's linear-alloc arrays, which are laid out anew in every process, so the values change from one
     * launch to the next and are aligned (the device's {@code un_h} — metasec reports the jmethodID of
     * {@code AwemeHostApplication.getPackageName()} — was 0xFB8F7E70, 0x3B10E640, 0xD70E1460 on three launches). unidbg's ids
     * are a hash of the signature: the same on every run, and not aligned.
     * <p>
     * Here a class's methods get consecutive slots in an array of their own, and its fields in another (ArtMethod is 32 bytes on arm64 —
     * declaring_class_, access_flags_, dex_method_index_, method_index_, hotness_count_, data_, entry_point —, ArtField 16:
     * declaring_class_, access_flags_, field_dex_idx_, offset_), each array placed afresh per launch from {@code seed}; an id
     * stays the same for the whole run. Class names keep unidbg's hash: a jclass is an indirect reference in ART, not an address.
     */
    static final class ArtIds implements com.github.unidbg.linux.android.dvm.HashFunction {

        private static final int ART_METHOD = 32;
        private static final int ART_FIELD = 16;

        private final java.util.Random random;
        private final Map<String, Integer> ids = new HashMap<>();
        private final Map<String, Long> cursors = new HashMap<>();
        private final Set<Integer> used = new HashSet<>();

        ArtIds(long seed) {
            this.random = new java.util.Random(seed);
        }

        @Override
        public synchronized int hash(String name) {
            int arrow = name.indexOf("->");
            if (arrow < 0) {
                return name.hashCode(); // a class: unidbg's own id
            }
            Integer id = ids.get(name);
            if (id != null) {
                return id;
            }
            boolean method = name.indexOf('(', arrow) >= 0;
            String owner = name.substring(0, arrow) + (method ? " methods" : " fields");
            Long cursor = cursors.get(owner);
            if (cursor == null) {
                cursor = random.nextLong() & 0xfffffff0L; // this launch's place for the array: 16-aligned, like the device's ids
            }
            int value = (int) (long) cursor;
            while (value == 0 || !used.add(value)) {
                cursor += method ? ART_METHOD : ART_FIELD;
                value = (int) (long) cursor;
            }
            cursors.put(owner, cursor + (method ? ART_METHOD : ART_FIELD));
            ids.put(name, value);
            return value;
        }
    }

    /**
     * {@code /data/data} as the device has it: a symlink to {@code /data/user/0}. The rootfs keeps the app's data only under
     * {@code data/user/0}, and unidbg follows no symlinks, so without this metasec's {@code faccessat}/{@code openat} of
     * {@code /data/data/<package>/files/mena.czl} failed where the device's succeeds (and {@code /data/data/<package>} itself was
     * ENOENT). Only paths that exist under {@code data/user/0} are answered; everything else goes on to the next resolver as before.
     */
    static final class DataDataAlias implements IOResolver<AndroidFileIO> {

        private static final String ALIAS = "/data/data";
        private static final String TARGET = "data/user/0";

        private final File rootDir;

        DataDataAlias(File rootDir) {
            this.rootDir = rootDir;
        }

        @Override
        public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
            if (pathname == null || !(pathname.equals(ALIAS) || pathname.startsWith(ALIAS + "/"))) {
                return null;
            }
            String rest = FilenameUtils.normalize(pathname.substring(ALIAS.length()), true);
            if (rest == null) {
                return null; // ".." above the alias
            }
            File file = new File(rootDir, TARGET + rest);
            if (file.isFile()) {
                return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, file, pathname));
            }
            if (file.isDirectory()) {
                return FileResult.<AndroidFileIO>success(new com.github.unidbg.linux.file.DirectoryFileIO(oflags, pathname, file));
            }
            return null;
        }
    }

    /**
     * Resolves a library the guest asks for by a device path from the test's rootfs, so the libraries are loaded the way the app's
     * {@code System.loadLibrary} does — through the guest's dlopen (unidbg's ld stub → memory.dlopen → this resolver → the file
     * system) — instead of handing the loader a host file. Multiple device paths are supported (metasec and the applog encryptor
     * live in the same emulator); the requested file name picks the one. Anything else goes to the fallback resolver.
     */
    static final class RootfsLibraryResolver implements LibraryResolver {


        private final LibraryResolver fallback;
        private final File rootDir;
        private final List<String> paths;

        RootfsLibraryResolver(LibraryResolver fallback, File rootDir, String path) {
            this(fallback, rootDir, new String[]{path});
        }

        RootfsLibraryResolver(LibraryResolver fallback, File rootDir, String... paths) {
            this.fallback = fallback;
            this.rootDir = rootDir;
            this.paths = new ArrayList<>();
            for (String path : paths) {
                this.paths.add(path);
            }
        }

        @Override
        public LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName) {
            String name = FilenameUtils.getName(libraryName);
            for (String path : paths) {
                if (!name.equals(FilenameUtils.getName(path))) {
                    continue;
                }
                File file = new File(rootDir, path);
                if (file.isFile()) {
                    return new ElfLibraryFile(file, emulator.is64Bit()) {
                        @Override
                        public String getPath() {
                            return path;
                        }
                    };
                }
            }
            return fallback.resolveLibrary(emulator, libraryName);
        }

        @Override
        public void onSetToLoader(Emulator<?> emulator) {
            fallback.onSetToLoader(emulator);
        }
    }

    
    static final class ShellReplay implements HookListener {

        private final Map<String, String> outputs = new HashMap<>();
        private final Map<String, Integer> exits = new HashMap<>();
        private final Emulator<?> emulator;
        private final Map<Long, long[]> streams = new HashMap<>(); // handle -> {command index, offset}

        /** commands = the profile's {@code shell_commands} (what each popen/system the device ran printed and returned) */
        ShellReplay(Emulator<?> emulator, JSONArray commands) {
            this.emulator = emulator;
            for (int i = 0; i < commands.size(); i++) {
                JSONObject command = commands.getJSONObject(i);
                String cmd = command.getString("cmd");
                JSONObject replay = command.getJSONObject("replay");
                if (cmd == null || replay == null) {
                    continue;
                }
                if (!outputs.containsKey(cmd)) {
                    outputs.put(cmd, replay.getString("stdout") == null ? "" : replay.getString("stdout"));
                    exits.put(cmd, replay.getIntValue("exit"));
                }
            }
        }

        @Override
        public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
            if (!"libc.so".equals(libraryName)) {
                return 0;
            }
            switch (symbolName) {
                case "popen":
                    return svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            String command = emulator.getContext().getPointerArg(0).getString(0);
                            int index = -1;
                            for (String known : outputs.keySet()) {
                                if (known.equals(command)) {
                                    index = known.hashCode();
                                }
                            }
                            if (index == -1) {
                                return HookStatus.LR(emulator, 0); // the recorded run did not run this command either
                            }
                            long handle = 0x5e110000L + (streams.size() + 1) * 0x100L; // a pointer the guest never dereferences
                            streams.put(handle, new long[]{index, 0});
                            if (MetasecSign.DEBUG) {
                                System.out.println("  [shell] popen(" + command + ") -> recorded output");
                            }
                            return HookStatus.LR(emulator, handle);
                        }
                    }).peer;
                case "fgets":
                    return svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            RegisterContext context = emulator.getContext();
                            UnidbgPointer buffer = context.getPointerArg(0);
                            int size = context.getIntArg(1);
                            long handle = context.getLongArg(2);
                            String text = read(handle, size);
                            if (text == null) {
                                return HookStatus.LR(emulator, 0);
                            }
                            buffer.write(0, text.getBytes(StandardCharsets.UTF_8), 0, text.getBytes(StandardCharsets.UTF_8).length);
                            buffer.setByte(text.getBytes(StandardCharsets.UTF_8).length, (byte) 0);
                            return HookStatus.LR(emulator, buffer.peer);
                        }
                    }).peer;
                case "pclose":
                case "fclose":
                    return svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            long handle = emulator.getContext().getLongArg(0);
                            long[] stream = streams.remove(handle);
                            return HookStatus.LR(emulator, stream == null ? 0 : exits.getOrDefault((int) stream[0], 0));
                        }
                    }).peer;
                case "system":
                    return svcMemory.registerSvc(new Arm64Hook() {
                        @Override
                        protected HookStatus hook(Emulator<?> emulator) {
                            String command = emulator.getContext().getPointerArg(0).getString(0);
                            Integer exit = exits.get(command);
                            if (MetasecSign.DEBUG) {
                                System.out.println("  [shell] system(" + command + ") -> " + (exit == null ? "not recorded" : "exit " + exit));
                            }
                            return HookStatus.LR(emulator, exit == null ? 127 : exit);
                        }
                    }).peer;
                default:
                    return 0;
            }
        }

        /** up to size-1 bytes of the next line (newline included), null at the end of the recorded output */
        private String read(long handle, int size) {
            long[] stream = streams.get(handle);
            if (stream == null) {
                return null;
            }
            String command = null;
            for (String known : outputs.keySet()) {
                if (known.hashCode() == stream[0]) {
                    command = known;
                }
            }
            String text = command == null ? "" : outputs.get(command);
            int offset = (int) stream[1];
            if (offset >= text.length()) {
                return null;
            }
            int end = text.indexOf('\n', offset);
            end = end < 0 || end - offset + 1 > size - 1 ? Math.min(text.length(), offset + size - 1) : end + 1;
            stream[1] = end;
            return text.substring(offset, end);
        }
    }
}
