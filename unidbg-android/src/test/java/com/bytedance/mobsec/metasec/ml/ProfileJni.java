package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.VarArg;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.array.IntArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.android.dvm.wrapper.DvmLong;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;

/**
 * Answers metasec's calls into Java from one device's recorded values ({@link DeviceProfile}): MS.b callbacks by cmd and
 * arguments, and its JNI calls by receiver class, method and arguments. Keva reads/writes (MS.b 0x1000022/0x1000023) go to the app's
 * Keva files; MS.b values the test sets on purpose override the record. Calls on java.lang value objects (String, Integer, Long,
 * Boolean, Float) are answered from the value, by {@link AbstractJni} where it can. A call with no matching record falls through to
 * {@link AbstractJni}, which reports it the usual unidbg way; {@link #missing()} lists them.
 */
class ProfileJni extends AbstractJni {

    private static final String MS_B = "com/bytedance/mobsec/metasec/ml/MS->b(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;";
    private static final Object NO_RECORD = new Object();

    private final DeviceProfile profile;
    private final Keva keva;
    private final Map<Integer, Object> msbOverrides;
    /** whether HTTP requests get the device's recorded responses (session.json network=recorded) or the answer of a failed request */
    private final boolean recordedNetwork;
    /** the guest's CLOCK_REALTIME in milliseconds */
    private final LongSupplier guestTime;
    /** a pointer in the recording -> the same pointer in this run (what the app later passes back to metasec) */
    final Map<Long, Long> pointers = new HashMap<>();
    private final Set<String> missing = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> answered = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Integer> calls = new HashMap<>();
    /** how many times each record answered a call on an object with an origin (see {@link #afterOrigin}) */
    private final Map<JSONObject, Integer> consumed = new java.util.IdentityHashMap<>();
    /** the record the last answer came from */
    private JSONObject chosen;
    /** every call metasec made, by MS.b cmd or JNI signature (metasec.countCalls prints them at the end) */
    final Map<String, Integer> callCounts = new java.util.concurrent.ConcurrentHashMap<>();
    /** fields metasec wrote (by object, or by class for static ones): later reads see them */
    private final Map<Object, Map<String, Object>> written = new IdentityHashMap<>();
    /**
     * This install's accelerometer, when the run gives it one ({@link #motion(Motion)}). metasec polls the sampling callback
     * every 10 s and reports the samples as a series, so a recorded answer is not enough: the replay clamps to the last one
     * and the device's accelerometer then reads as frozen for the rest of the session. Null leaves the recorded answers alone.
     */
    private Motion motion;
    /**
     * The profile answers that are a moment rather than a property, and the rule each follows ({@code device/dynamic.json}).
     * Null leaves every recorded answer exactly as it is.
     */
    private DynamicValues dynamic;

    /** @param msbOverrides MS.b answers (recorded encoding, by cmd) that replace the recorded ones */
    ProfileJni(DeviceProfile profile, Keva keva, Map<Integer, Object> msbOverrides, boolean recordedNetwork, LongSupplier guestTime) {
        this.profile = profile;
        this.keva = keva;
        this.msbOverrides = msbOverrides;
        this.recordedNetwork = recordedNetwork;
        this.guestTime = guestTime;
    }

    /** give this run an accelerometer of its own; without one the recorded samples are replayed as before */
    void motion(Motion own) {
        this.motion = own;
    }

    /** govern the answers that are a moment of this phone; without this every recorded answer stands as recorded */
    void dynamic(DynamicValues values) {
        this.dynamic = values;
    }

    /** a recorded value as the Java object metasec gets */
    DvmObject<?> value(VM vm, Object recorded) {
        return toObject((BaseVM) vm, recorded, null);
    }

    /** calls that had no record, with what was recorded for the same method */
    Set<String> missing() {
        return missing;
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (MS_B.equals(signature)) {
            return msb(vm, vaList);
        }
        return toObject(vm, answer(vm, null, dvmClass, signature, vaList), () -> super.callStaticObjectMethodV(vm, dvmClass, signature, vaList));
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (MS_B.equals(signature)) {
            return msb(vm, varArg);
        }
        return toObject(vm, answer(vm, null, dvmClass, signature, varArg), () -> super.callStaticObjectMethod(vm, dvmClass, signature, varArg));
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        DvmObject<?> service = service(vm, signature, vaList);
        if (service != null) {
            return service;
        }
        return toObject(vm, answer(vm, dvmObject, null, signature, vaList), () -> super.callObjectMethodV(vm, dvmObject, signature, vaList));
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        DvmObject<?> service = service(vm, signature, varArg);
        if (service != null) {
            return service;
        }
        return toObject(vm, answer(vm, dvmObject, null, signature, varArg), () -> super.callObjectMethod(vm, dvmObject, signature, varArg));
    }

    private static final String GET_SERVICE = "android/os/IServiceManager->getService(Ljava/lang/String;)Landroid/os/IBinder;";
    private static final String PACKAGE_SERVICE = "package";

    /**
     * unidbg's {@code SystemService} resolves a fixed list of services and throws {@code BackendException} for {@code "package"};
     * metasec on API 34 reaches PackageManager through the binder instead of the {@code ApplicationPackageManager} calls the
     * recording has, and the exception ends the collection before the rest of it runs. It gets a proxy instead, answered below
     * from the same recorded values.
     */
    private DvmObject<?> service(BaseVM vm, String signature, VarArg args) {
        if (!GET_SERVICE.equals(signature)) {
            return null;
        }
        DvmObject<?> name = args.getObjectArg(0);
        if (!(name instanceof StringObject) || !PACKAGE_SERVICE.equals(((StringObject) name).getValue())) {
            return null;
        }
        System.out.println("  [binder] IServiceManager.getService(\"" + PACKAGE_SERVICE + "\") -> IPackageManager proxy");
        return vm.resolveClass("android/content/pm/IPackageManager$Stub$Proxy").newObject(PACKAGE_SERVICE);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        return toObject(vm, answer(vm, null, dvmClass, signature, null), () -> super.getStaticObjectField(vm, dvmClass, signature));
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        return toObject(vm, answer(vm, dvmObject, null, signature, null), () -> super.getObjectField(vm, dvmObject, signature));
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        return toInt(answer(vm, null, dvmClass, signature, vaList), () -> super.callStaticIntMethodV(vm, dvmClass, signature, vaList));
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        return toInt(answer(vm, null, dvmClass, signature, varArg), () -> super.callStaticIntMethod(vm, dvmClass, signature, varArg));
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        return toInt(answer(vm, dvmObject, null, signature, vaList), () -> super.callIntMethodV(vm, dvmObject, signature, vaList));
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        return toInt(answer(vm, dvmObject, null, signature, varArg), () -> super.callIntMethod(vm, dvmObject, signature, varArg));
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        return toInt(answer(vm, null, dvmClass, signature, null), () -> super.getStaticIntField(vm, dvmClass, signature));
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        return toInt(answer(vm, dvmObject, null, signature, null), () -> super.getIntField(vm, dvmObject, signature));
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        return toInt(answer(vm, null, dvmClass, signature, vaList), () -> super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList) ? 1 : 0) != 0;
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        return toInt(answer(vm, null, dvmClass, signature, varArg), () -> super.callStaticBooleanMethod(vm, dvmClass, signature, varArg) ? 1 : 0) != 0;
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        return toInt(answer(vm, dvmObject, null, signature, vaList), () -> super.callBooleanMethodV(vm, dvmObject, signature, vaList) ? 1 : 0) != 0;
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        return toInt(answer(vm, dvmObject, null, signature, varArg), () -> super.callBooleanMethod(vm, dvmObject, signature, varArg) ? 1 : 0) != 0;
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature) {
        return toInt(answer(vm, null, dvmClass, signature, null), () -> super.getStaticBooleanField(vm, dvmClass, signature) ? 1 : 0) != 0;
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        return toInt(answer(vm, dvmObject, null, signature, null), () -> super.getBooleanField(vm, dvmObject, signature) ? 1 : 0) != 0;
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        return toLong(answer(vm, null, dvmClass, signature, vaList), () -> super.callStaticLongMethodV(vm, dvmClass, signature, vaList));
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        return toLong(answer(vm, null, dvmClass, signature, varArg), () -> super.callStaticLongMethod(vm, dvmClass, signature, varArg));
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        return toLong(answer(vm, dvmObject, null, signature, vaList), () -> super.callLongMethodV(vm, dvmObject, signature, vaList));
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        return toLong(answer(vm, dvmObject, null, signature, varArg), () -> super.callLongMethod(vm, dvmObject, signature, varArg));
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature) {
        return toLong(answer(vm, null, dvmClass, signature, null), () -> super.getStaticLongField(vm, dvmClass, signature));
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        return toLong(answer(vm, dvmObject, null, signature, null), () -> super.getLongField(vm, dvmObject, signature));
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (answer(vm, null, dvmClass, signature, vaList) == NO_RECORD) {
            super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (answer(vm, null, dvmClass, signature, varArg) == NO_RECORD) {
            super.callStaticVoidMethod(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (answer(vm, dvmObject, null, signature, vaList) == NO_RECORD) {
            super.callVoidMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (answer(vm, dvmObject, null, signature, varArg) == NO_RECORD) {
            super.callVoidMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("java/lang/Float->floatValue()F".equals(signature)) {
            return (Float) dvmObject.getValue();
        }
        return super.callFloatMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature, DvmObject<?> value) {
        write(dvmObject, signature, value);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, String signature, int value) {
        write(dvmObject, signature, value);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, String signature, long value) {
        write(dvmObject, signature, value);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature, boolean value) {
        write(dvmObject, signature, value ? 1 : 0);
    }

    @Override
    public void setStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature, DvmObject<?> value) {
        write(dvmClass, signature, value);
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, String signature, int value) {
        write(dvmClass, signature, value);
    }

    @Override
    public void setStaticLongField(BaseVM vm, DvmClass dvmClass, String signature, long value) {
        write(dvmClass, signature, value);
    }

    @Override
    public void setStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature, boolean value) {
        write(dvmClass, signature, value ? 1 : 0);
    }

    private void write(Object owner, String signature, Object value) {
        Map<String, Object> fields;
        synchronized (written) {
            fields = written.get(owner);
        }
        if (fields == null) {
            synchronized (written) {
                written.put(owner, fields = new HashMap<>());
            }
        }
        fields.put(signature, value);
        log("set " + signature, value);
    }

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        return valueClass(signature) ? super.newObjectV(vm, dvmClass, signature, vaList) : construct(dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        return valueClass(signature) ? super.newObject(vm, dvmClass, signature, varArg) : construct(dvmClass, signature, varArg);
    }

    /** a Java object metasec creates (an IntentFilter to pass on...): a handle that remembers its constructor arguments */
    private DvmObject<?> construct(DvmClass dvmClass, String signature, VarArg varArg) {
        List<Object> args = args(varArg, signature.substring(signature.indexOf("->") + 2));
        return log("new " + signature + " " + args, dvmClass.newObject(args));
    }

    private static boolean valueClass(String signature) {
        return signature.startsWith("java/lang/String->") || signature.startsWith("java/lang/Integer->") ||
                signature.startsWith("java/lang/Long->") || signature.startsWith("java/lang/Boolean->") || signature.startsWith("java/lang/Float->");
    }

    private String endpoint; // the endpoint of the HTTP request being answered
    private int mssdkDumps;

    /**
     * Diagnostic (metasec.dumpMssdk): the request metasec built for an HTTP call and the answer it got, one pair per call, so the
     * request can be compared with the device's captured plaintext.
     */
    private void dumpMssdk(DvmObject<?> o, Object ret, String url) {
        if (!Boolean.getBoolean("metasec.dumpMssdk")) {
            return;
        }
        try {
            File dir = new File("target/mssdk");
            dir.mkdirs();
            int n = ++mssdkDumps;
            String path = url == null ? "" : url.split("[?]", 2)[0];
            String name = path.substring(path.lastIndexOf('/') + 1);
            if (o instanceof ArrayObject) {
                DvmObject<?>[] values = ((ArrayObject) o).getValue();
                if (values.length > 0 && values[0] instanceof ByteArray) {
                    FileUtils.writeByteArrayToFile(new File(dir, String.format("%02d-%s-req.bin", n, name)), ((ByteArray) values[0]).getValue());
                }
            }
            if (ret instanceof JSONObject) {
                JSONArray values = ((JSONObject) ret).getJSONArray("v");
                if (values != null && values.size() > 1 && values.get(1) instanceof JSONObject) {
                    String hex = ((JSONObject) values.get(1)).getString("hex");
                    if (hex != null) {
                        FileUtils.writeByteArrayToFile(new File(dir, String.format("%02d-%s-resp.bin", n, name)), Hex.decodeHex(hex.toCharArray()));
                    }
                }
            }
        } catch (IOException | DecoderException e) {
            throw new IllegalStateException(e);
        }
    }

    /** MS.b(int cmd, int p1, long l, String s, Object o) */
    private DvmObject<?> msb(BaseVM vm, VarArg varArg) {
        int cmd = varArg.getIntArg(0);
        int p1 = varArg.getIntArg(1);
        long l = varArg.getLongArg(2);
        DvmObject<?> s = varArg.getObjectArg(3);
        DvmObject<?> o = varArg.getObjectArg(4);
        String name = "MS.b(" + DeviceProfile.hex(cmd) + ")";
        callCounts.merge(name, 1, Integer::sum);
        if (msbOverrides.containsKey(cmd)) {
            return log(name + " (set by the test)", toObject(vm, msbOverrides.get(cmd), null));
        }
        if (cmd == 0x30001) {
            dumpMssdk(o, null, s == null ? null : string(s));
        }
        if (cmd == 0x30001 && !recordedNetwork) {
            // Java sends metasec's HTTP request (ms.bd.c.x4.LJFF); the local test has no network: what LJFF returns when it throws
            return log(name + " (no network) " + (s == null ? null : string(s)), failedRequest(vm));
        }
        switch (cmd) {
            case 0x1000013: { // the accelerometer: the samples taken since the last poll (doc/mssdk-report-fields.md /#9/#3)
                if (motion == null) {
                    break;      // no motion model: the recorded answers, as before
                }
                // null on a first poll whose buffer has not filled, as the recording's own first answer was
                String samples = motion.sample(guestTime.getAsLong());
                return log(name + " (accelerometer, " + motion.activity() + " at "
                                + String.format("%.1f", motion.tiltDegrees()) + " deg)",
                        samples == null ? null : new StringObject(vm, samples));
            }
            case 0x1000022: { // Keva read: s = repository, o = key
                String value = keva.get(string(s), string(o));
                return log(name + " keva " + string(o), value == null ? null : new StringObject(vm, value));
            }
            case 0x1000023: { // Keva write: s = "repository|key", o = value
                String[] repoKey = string(s).split("\\|", 2);
                keva.put(repoKey[0], repoKey[1], string(o));
                return log(name + " keva " + repoKey[1] + " = " + string(o), null);
            }
            default:
                break;
        }
        List<JSONObject> records = profile.msb(cmd);
        List<JSONObject> matched = new ArrayList<>();
        for (JSONObject record : records) {
            JSONObject args = record.getJSONObject("args");
            // an HTTP request's body and the request counters change every time; its endpoint does not
            if ((cmd == 0x30001 || matches(args.get("p1"), p1) && matches(args.get("o"), o)) && sameRequest(cmd, args.get("s"), s)) {
                matched.add(record);
                long recorded = Long.decode(args.getString("l"));
                if (recorded != 0 && l != 0) {
                    pointers.put(recorded, l);
                }
            }
        }
        Object ret = inOrder(name + " " + p1 + " " + s + " " + describe(o), matched);
        if (ret == NO_RECORD && !records.isEmpty() && allNull(records)) {
            ret = null; // a sink: every recorded call returned null (event reports, logs)
        }
        if (cmd == 0x30001) {
            dumpMssdk(o, ret, s == null ? null : string(s));
        }
        if (cmd == 0x30001 && ret != NO_RECORD) {
            endpoint = s == null ? "?" : string(s).split("\\?", 2)[0];
            ret = liveResponse(ret);
        }
        if (ret == NO_RECORD) {
            noRecord(name + " p1=" + p1 + " s=" + s + " o=" + describe(o), records);
            if (cmd == 0x30001) {
                // an endpoint the recording does not have: the app's request fails, as without network
                return failedRequest(vm);
            }
            // an unrecorded callback must not kill the calling thread: answer null and keep it in the missing list
            return null;
        }
        if (ret instanceof String) {
            ret = DeviceProfile.resolve((String) ret);
        }
        return log(name, toObject(vm, ret, null));
    }

    /** this example signs offline: metasec's mssdk requests are answered from the recording, never sent */
    void holdMssdk(boolean on) {
    }

    /** what the app's HTTP helper returns when the request throws: code -1, no body, error 99999 */
    private static DvmObject<?> failedRequest(BaseVM vm) {
        return new ArrayObject(new DvmObject<?>[]{new StringObject(vm, "-1"), null, DvmInteger.valueOf(vm, 99999)});
    }

    /** a recorded HTTP response as the server would answer now: its own server timestamps moved to the guest's clock */
    private Object liveResponse(Object recorded) {
        JSONObject response = (JSONObject) recorded;
        JSONArray values0 = response.getJSONArray("v");
        int bytes = 0;
        for (int i = 0; i < values0.size(); i++) {
            Object value = values0.get(i);
            if (value instanceof JSONObject && "[B".equals(((JSONObject) value).getString("cls"))) {
                bytes = ((JSONObject) value).getString("hex").length() / 2;
            }
        }
        System.out.printf("  [mssdk] %s -> %s, %d-byte body (recorded, server time = guest clock)%n",
                endpoint, values0.get(0), bytes);
        JSONArray values = response.getJSONArray("v");
        for (int i = 0; i < values.size(); i++) {
            Object value = values.get(i);
            if (value instanceof JSONObject && "[B".equals(((JSONObject) value).getString("cls"))) {
                try {
                    JSONObject copy = (JSONObject) value;
                    byte[] body = Hex.decodeHex(copy.getString("hex").toCharArray());
                    copy.put("hex", Hex.encodeHexString(ServerTime.now(body, guestTime.getAsLong())));
                    values.set(i, copy);
                } catch (DecoderException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        return response;
    }

    /**
     * The recorded answer of a JNI call, or {@link #NO_RECORD}. Recorded keys use the receiver's runtime class (static: the class),
     * {@code class.name(desc)ret} for methods and {@code class.nameDesc} for fields.
     */
    private Object answer(BaseVM vm, DvmObject<?> self, DvmClass dvmClass, String signature, VarArg varArg) {
        if (Boolean.getBoolean("metasec.countCalls")) {
            callCounts.merge(signature.substring(signature.indexOf("->") + 2), 1, Integer::sum);
        }
        if (valueClass(signature)) {
            return valueSemantics(vm, self, signature, varArg);
        }
        Map<String, Object> fields = varArg == null ? written.get(self == null ? dvmClass : self) : null;
        if (fields != null && fields.containsKey(signature)) {
            return fields.get(signature);
        }
        int arrow = signature.indexOf("->");
        String member = signature.substring(arrow + 2).replace(":", "");
        String owner = self == null ? dvmClass.getClassName() : self.getObjectType().getClassName();
        String key = owner.replace('/', '.') + "." + member;
        List<JSONObject> records = profile.jni(key);
        if (records.isEmpty()) {
            key = signature.substring(0, arrow).replace('/', '.') + "." + member;
            records = profile.jni(key);
        }
        List<Object> args = varArg == null ? new ArrayList<>() : args(varArg, member);
        List<JSONObject> matched = new ArrayList<>();
        for (JSONObject record : records) {
            JSONArray recorded = record.getJSONArray("args");
            boolean match = recorded.size() == args.size();
            for (int i = 0; match && i < args.size(); i++) {
                match = matches(recorded.get(i), args.get(i));
            }
            if (match) {
                matched.add(record);
            }
        }
        chosen = null;
        Object ret = afterOrigin(self, key + " " + args, matched);
        if (ret == NO_RECORD) {
            ret = inOrder(key + " " + args, matched);
        }
        if (ret == NO_RECORD) {
            noRecord(key + " " + args, records);
            return NO_RECORD;
        }
        if (ret instanceof String) {
            ret = DeviceProfile.resolve((String) ret); // a new install's own values (did, install time) where the profile has tokens
        }
        // an answer that is a moment of this phone rather than a property of its model (device/dynamic.json). One point for
        // every such field: the recording froze each entry at the millisecond it was captured and cannot say it may have moved
        if (dynamic != null && dynamic.governs(key)) {
            // the argument that picks which value this is, for calls that answer many keys (Settings.System.getInt)
            String which = null;
            for (Object arg : args) {
                if (arg instanceof String) {
                    which = (String) arg;
                    break;
                }
            }
            ret = dynamic.answer(key, which, ret, guestTime.getAsLong());
        }
        log(key, ret);
        return withOrigin(ret);
    }

    /**
     * An object a recorded call returned remembers where it came from (the record's thread and time), so the calls later made on
     * it are answered from what the device answered for that object: a Bundle from ContentResolver.call(GET_secure, android_id)
     * gets the getString("value") that followed that call on the device, not the n-th getString of the whole recording
     * (29 of them, for 29 different settings).
     */
    private Object withOrigin(Object ret) {
        if (!(ret instanceof JSONObject) || chosen == null || String.valueOf(((JSONObject) ret).getString("cls")).startsWith("[")) {
            return ret;
        }
        JSONObject object = (JSONObject) ((JSONObject) ret).clone();
        object.put("_thread", chosen.getString("thread"));
        object.put("_t", chosen.getLongValue("t_ms"));
        return object;
    }

    /**
     * For a call on an object with an origin, when the device answered the call differently over time: the answers that call got
     * on the origin's thread from the origin on, in order. NO_RECORD when there is none (then the answers over the whole recording).
     */
    private Object afterOrigin(DvmObject<?> self, String call, List<JSONObject> matched) {
        Object value = self == null ? null : self.getValue();
        if (!(value instanceof JSONObject) || !((JSONObject) value).containsKey("_t") || matched.size() < 2) {
            return NO_RECORD;
        }
        String thread = ((JSONObject) value).getString("_thread");
        long t = ((JSONObject) value).getLongValue("_t");
        List<JSONObject> after = new ArrayList<>();
        for (JSONObject record : matched) {
            if (Objects.equals(thread, record.getString("thread")) && record.getLongValue("t_ms") >= t) {
                after.add(record);
            }
        }
        if (after.isEmpty()) {
            return NO_RECORD;
        }
        after.sort(Comparator.comparingLong(record -> record.getLongValue("t_ms")));
        // the first answer from the origin on that no other object took: objects made in a batch and asked afterwards (a sensor
        // list, then getType on each) get theirs in turn
        chosen = after.get(after.size() - 1);
        for (JSONObject record : after) {
            int used = consumed.getOrDefault(record, 0);
            if (used < Math.max(1, record.getIntValue("count"))) {
                consumed.put(record, used + 1);
                chosen = record;
                break;
            }
        }
        return chosen.get("ret");
    }

    /** the records with each one as many times as it happened in a row ("count": the recorder folds repeats) */
    private static List<JSONObject> repeated(List<JSONObject> records) {
        List<JSONObject> calls = new ArrayList<>();
        for (JSONObject record : records) {
            for (int i = 0; i < Math.max(1, record.getIntValue("count")); i++) {
                calls.add(record);
            }
        }
        return calls;
    }

    /** java.lang value objects: the ones {@link AbstractJni} does not answer (it does String.getBytes, Integer.intValue...) */
    private static Object valueSemantics(BaseVM vm, DvmObject<?> self, String signature, VarArg varArg) {
        switch (signature) {
            case "java/lang/Integer->valueOf(I)Ljava/lang/Integer;":
                return DvmInteger.valueOf(vm, varArg.getIntArg(0));
            case "java/lang/Long->valueOf(J)Ljava/lang/Long;":
                return DvmLong.valueOf(vm, varArg.getLongArg(0));
            case "java/lang/Boolean->valueOf(Z)Ljava/lang/Boolean;":
                return DvmBoolean.valueOf(vm, varArg.getIntArg(0) != 0);
            case "java/lang/Long->longValue()J":
                return ((DvmLong) self).getValue();
            case "java/lang/Boolean->booleanValue()Z":
                return ((DvmBoolean) self).getValue() ? 1 : 0;
            case "java/lang/Integer->toString()Ljava/lang/String;":
                return new StringObject(vm, String.valueOf(((DvmInteger) self).getValue()));
            default:
                return NO_RECORD;
        }
    }

    private static List<Object> args(VarArg varArg, String member) {
        String params = member.substring(member.indexOf('(') + 1, member.indexOf(')'));
        List<Object> args = new ArrayList<>();
        for (int i = 0, index = 0; i < params.length(); index++) {
            char type = params.charAt(i);
            int end = i;
            while (params.charAt(end) == '[') {
                end++;
            }
            if (params.charAt(end) == 'L') {
                end = params.indexOf(';', end);
            }
            if (type == 'L' || type == '[') {
                args.add(varArg.getObjectArg(index));
            } else if (type == 'J') {
                args.add(varArg.getLongArg(index));
            } else if (type == 'F') {
                args.add(varArg.getFloatArg(index));
            } else if (type == 'D') {
                args.add(varArg.getDoubleArg(index));
            } else {
                args.add(varArg.getIntArg(index));
            }
            i = end + 1;
        }
        return args;
    }

    /**
     * Whether the recorded URL is the request being made. The app sends HTTP requests (MS.b 0x30001) to the same endpoints with
     * query strings that carry the session's ids, so the endpoint path decides; any other string must match exactly.
     */
    private static boolean sameRequest(int cmd, Object recorded, Object actual) {
        if (cmd != 0x30001 || !(recorded instanceof String) || !(actual instanceof StringObject)) {
            return matches(recorded, actual);
        }
        String request = ((StringObject) actual).getValue();
        return ((String) recorded).split("\\?", 2)[0].equals(request.split("\\?", 2)[0]);
    }

    /** whether a recorded value describes the actual one */
    private static boolean matches(Object recorded, Object actual) {
        if (recorded == null || actual == null) {
            return recorded == null && actual == null;
        }
        if (actual instanceof Integer) {
            return recorded instanceof Number ? ((Number) recorded).longValue() == (Integer) actual :
                    recorded instanceof String && ((String) recorded).startsWith("0x") && Long.decode((String) recorded).longValue() == (Integer) actual;
        }
        if (actual instanceof Long) {
            return recorded instanceof Number ? ((Number) recorded).longValue() == (Long) actual :
                    recorded instanceof String && ((String) recorded).startsWith("0x") && Long.parseUnsignedLong(((String) recorded).substring(2), 16) == (Long) actual;
        }
        if (actual instanceof StringObject) {
            // a first-launch profile writes the install's values as tokens ({{did}}): compare with them filled in
            Object value = recorded instanceof String ? DeviceProfile.resolve((String) recorded) : recorded;
            return value.equals(((StringObject) actual).getValue());
        }
        if (actual instanceof DvmInteger || actual instanceof DvmLong || actual instanceof DvmBoolean) {
            return recorded.equals(boxed((DvmObject<?>) actual));
        }
        if (!(recorded instanceof JSONObject) || !(actual instanceof DvmObject)) {
            return false;
        }
        JSONObject value = (JSONObject) recorded;
        DvmObject<?> object = (DvmObject<?>) actual;
        if (object instanceof ByteArray) {
            return "[B".equals(value.getString("cls")) && Hex.encodeHexString(((ByteArray) object).getValue()).equals(value.getString("hex"));
        }
        if (object instanceof ArrayObject) {
            JSONArray elements = value.getJSONArray("v");
            DvmObject<?>[] array = ((ArrayObject) object).getValue();
            if (elements == null || elements.size() != array.length) {
                return false;
            }
            for (int i = 0; i < array.length; i++) {
                if (!matches(elements.get(i), array[i])) {
                    return false;
                }
            }
            return true;
        }
        return object.getObjectType().getClassName().replace('/', '.').equals(value.getString("cls"));
    }

    private static String boxed(DvmObject<?> object) {
        String type = object instanceof DvmInteger ? "Integer" : object instanceof DvmLong ? "Long" :
                object instanceof DvmBoolean ? "Boolean" : "Float";
        return type + ":" + object.getValue();
    }

    private DvmObject<?> toObject(BaseVM vm, Object value, Fallback<DvmObject<?>> fallback) {
        if (value == NO_RECORD) {
            return fallback.call();
        }
        if (value == null || value instanceof DvmObject) {
            return (DvmObject<?>) value;
        }
        if (value instanceof String) {
            String string = (String) value;
            int colon = string.indexOf(':');
            String type = colon == -1 ? "" : string.substring(0, colon);
            switch (type) {
                case "Integer":
                    return DvmInteger.valueOf(vm, Integer.parseInt(string.substring(colon + 1)));
                case "Long":
                    return DvmLong.valueOf(vm, Long.parseLong(string.substring(colon + 1)));
                case "Boolean":
                    return DvmBoolean.valueOf(vm, Boolean.parseBoolean(string.substring(colon + 1)));
                case "Float": // unidbg has no wrapper for it: a java/lang/Float holding the value
                    return vm.resolveClass("java/lang/Float").newObject(Float.parseFloat(string.substring(colon + 1)));
                default:
                    return new StringObject(vm, string);
            }
        }
        JSONObject object = (JSONObject) value;
        String cls = object.getString("cls");
        if ("[B".equals(cls)) {
            try {
                return new ByteArray(vm, Hex.decodeHex(object.getString("hex").toCharArray()));
            } catch (DecoderException e) {
                throw new IllegalStateException(e);
            }
        }
        if ("[I".equals(cls)) {
            JSONArray elements = object.getJSONArray("v");
            int[] array = new int[elements.size()];
            for (int i = 0; i < array.length; i++) {
                array[i] = elements.getIntValue(i);
            }
            return new IntArray(vm, array);
        }
        if (cls.startsWith("[")) {
            JSONArray elements = object.getJSONArray("v");
            DvmObject<?>[] array = new DvmObject<?>[elements.size()];
            for (int i = 0; i < array.length; i++) {
                array[i] = toObject(vm, elements.get(i), null);
            }
            return new ArrayObject(array);
        }
        return vm.resolveClass(cls.replace('.', '/')).newObject(object);
    }

    private static int toInt(Object value, Fallback<Integer> fallback) {
        if (value == NO_RECORD) {
            return fallback.call();
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        String string = (String) value;
        return string.startsWith("0x") ? Long.decode(string).intValue() : Integer.parseInt(string.substring(string.indexOf(':') + 1));
    }

    private static long toLong(Object value, Fallback<Long> fallback) {
        if (value == NO_RECORD) {
            return fallback.call();
        }
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        String string = (String) value;
        return string.startsWith("0x") ? Long.parseUnsignedLong(string.substring(2), 16) : Long.parseLong(string.substring(string.indexOf(':') + 1));
    }

    /**
     * The answer to a call that matched these records: theirs when they agree; when the device answered the same call differently
     * over time (settings that arrived later...), the recorded answers in recorded order, one per call, then the last one.
     */
    private Object inOrder(String call, List<JSONObject> matched) {
        if (matched.isEmpty()) {
            return NO_RECORD;
        }
        matched.sort(Comparator.comparingLong(record -> record.getLongValue("t_ms")));
        matched = repeated(matched);
        int index = Math.min(calls.merge(call, 1, Integer::sum) - 1, matched.size() - 1);
        chosen = matched.get(index);
        Object ret = chosen.get("ret");
        for (JSONObject record : matched) {
            if ((!Objects.equals(record.get("ret"), ret) || index > 0) && MetasecSign.DEBUG) {
                System.out.printf("  [recorded, call %d of %d answers over time] %s%n", index + 1, matched.size(), abbreviate(call));
                break;
            }
        }
        return ret;
    }

    private static boolean allNull(List<JSONObject> records) {
        for (JSONObject record : records) {
            if (record.get("ret") != null) {
                return false;
            }
        }
        return true;
    }

    private void noRecord(String call, List<JSONObject> records) {
        String why;
        if (records.isEmpty()) {
            why = "not recorded";
        } else {
            List<Object> recorded = new ArrayList<>();
            for (JSONObject record : records) {
                recorded.add(record.get("args"));
            }
            why = "recorded only with other arguments: " + abbreviate(recorded.toString());
        }
        if (missing.add(call + " -- " + why)) {
            System.out.println("  [no record] " + call + " -- " + why);
        }
    }

    private <T> T log(String key, T value) {
        int count = answered.merge(key, 1, Integer::sum);
        if (count <= 2 && MetasecSign.DEBUG) {
            System.out.println("  [recorded] " + key + " -> " + abbreviate(describe(value)));
        }
        return value;
    }

    private static String describe(Object value) {
        if (value instanceof ByteArray) {
            return "byte[" + ((ByteArray) value).getValue().length + "]";
        }
        if (value instanceof ArrayObject) {
            return Arrays.toString(((ArrayObject) value).getValue());
        }
        return String.valueOf(value);
    }

    private static String abbreviate(String text) {
        return text == null || text.length() <= 300 ? text : text.substring(0, 300) + "...(" + text.length() + ")";
    }

    private static String string(DvmObject<?> object) {
        return object == null ? null : ((StringObject) object).getValue();
    }

    private interface Fallback<T> {
        T call();
    }

    /**
     * metasec looks up a native {@code MS.a()V} that the app does not have (run4: {@code GetStaticMethodID} fails), so that one
     * signature is left to unidbg's usual "not found" answer.
     */
    @Override
    public boolean acceptMethod(DvmClass dvmClass, String signature, boolean isStatic) {
        return !"com/bytedance/mobsec/metasec/ml/MS->a()V".equals(signature)
                && super.acceptMethod(dvmClass, signature, isStatic);
    }

    
    static final class ServerTime {

        /** epoch milliseconds of a sane server clock: the timestamps a recorded response can carry */
        private static final long MIN = 1500000000000L, MAX = 2000000000000L;

        private ServerTime() {
        }

        static byte[] now(byte[] body, long nowMillis) {
            if (body == null) {
                return null;
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream(body.length);
            int i = 0;
            while (i < body.length) {
                long tag = 0;
                int shift = 0;
                int start = i;
                int b;
                do {
                    if (i >= body.length) {
                        return body;
                    }
                    b = body[i++] & 0xff;
                    tag |= (long) (b & 0x7f) << shift;
                    shift += 7;
                } while ((b & 0x80) != 0);
                int wire = (int) (tag & 7);
                out.write(body, start, i - start);
                int valueStart = i;
                switch (wire) {
                    case 0: { // varint
                        long value = 0;
                        shift = 0;
                        do {
                            if (i >= body.length) {
                                return body;
                            }
                            b = body[i++] & 0xff;
                            value |= (long) (b & 0x7f) << shift;
                            shift += 7;
                        } while ((b & 0x80) != 0);
                        if (value >= MIN && value <= MAX) {
                            writeVarint(out, nowMillis);
                        } else {
                            out.write(body, valueStart, i - valueStart);
                        }
                        break;
                    }
                    case 1: // fixed64
                    case 5: // fixed32
                        i += wire == 1 ? 8 : 4;
                        if (i > body.length) {
                            return body;
                        }
                        out.write(body, valueStart, i - valueStart);
                        break;
                    case 2: { // length-delimited
                        long length = 0;
                        shift = 0;
                        do {
                            if (i >= body.length) {
                                return body;
                            }
                            b = body[i++] & 0xff;
                            length |= (long) (b & 0x7f) << shift;
                            shift += 7;
                        } while ((b & 0x80) != 0);
                        out.write(body, valueStart, i - valueStart); // the length prefix is unchanged
                        if (length < 0 || i + length > body.length) {
                            return body;
                        }
                        out.write(body, i, (int) length);
                        i += (int) length;
                        break;
                    }
                    default:
                        return body; // groups and unknown wire types: leave the body as recorded
                }
            }
            return out.toByteArray();
        }

        private static void writeVarint(ByteArrayOutputStream out, long value) {
            while ((value & ~0x7fL) != 0) {
                out.write((int) ((value & 0x7f) | 0x80));
                value >>>= 7;
            }
            out.write((int) value);
        }
    }
}
