package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * The profile answers that are a moment of a phone rather than a property of its model.
 *
 * <p>The profile is a recording: every entry is frozen at the millisecond it was captured, and the format cannot say "this may
 * have changed since". {@code getStreamVolume} has exactly one record - {@code {"args":[1],"ret":5,"count":6}}, asked six times
 * and answered 5 six times - so a cohort derived from it is a cohort with one owner, at one moment, forever. This supplies the
 * missing notion, in one place: {@link ProfileJni} funnels every profile answer through {@link #answer}, so a field becomes
 * dynamic by being named in {@code device/dynamic.json} rather than by another patch in the emulation code.
 *
 * <p>The division of labour is deliberate. Which values move, how far and how often is data ({@code dynamic.json}); the clock
 * and the invariants are code. This class never reads a precomputed timeline: the guest clock advances by executed
 * instructions, not wall time, so a timeline computed outside would desync as soon as the emulator ran fast or slow, and no
 * recording of a real phone's volume over an hour exists to build one from. A rule is honest about being a rule.
 *
 * <p>State that has to survive the app closing - where the battery was, how the phone was lying, when it was last opened -
 * lives in the install's own ledger ({@code state.json}, see {@link DeviceState}), not here and not in the fingerprint.
 */
class DynamicValues {

    /** the rule for one answer, as the data file states it */
    private static final class Rule {
        private final String kind;
        private final JSONObject spec;
        /** the value this run settled on, once drawn */
        private Object value;
        /** for occasionally_changes: the guest moment the value is next due to jump */
        private long nextChangeAt = Long.MIN_VALUE;

        private Rule(String kind, JSONObject spec) {
            this.kind = kind;
            this.spec = spec;
        }
    }

    private final Random random;
    private final Map<String, Rule> rules = new LinkedHashMap<>();
    private final JSONObject ledger;

    /**
     * @param dataFile {@code device/dynamic.json}: which answers are moments, and the rule for each
     * @param random   this install's own draw, seeded from its id so one install is one phone across its launches
     * @param ledger   what the last launch left behind ({@link DeviceState}), or null for an install opening for the first time
     */
    DynamicValues(File dataFile, Random random, JSONObject ledger) throws IOException {
        this.random = random;
        this.ledger = ledger == null ? new JSONObject() : ledger;
        JSONObject data = JSON.parseObject(
                org.apache.commons.io.FileUtils.readFileToString(dataFile, java.nio.charset.StandardCharsets.UTF_8));
        for (Map.Entry<String, Object> entry : data.getJSONObject("values").entrySet()) {
            JSONObject spec = (JSONObject) entry.getValue();
            rules.put(entry.getKey(), new Rule(spec.getString("kind"), spec));
        }
    }

    /** whether this answer is governed by a rule (the model-backed ones are driven by their own model, not from here) */
    boolean governs(String key) {
        Rule rule = rules.get(key);
        return rule != null && rule.spec.getString("model") == null;
    }

    /**
     * The value this answer should have at this moment of the launch, or {@code recorded} when no rule covers it.
     *
     * @param key      the profile's own key for the answer (a JNI signature, or {@code MS.b(0x...)})
     * @param argument the argument that selects which value this is, for answers that serve many keys
     *                 ({@code Settings.System.getInt}); null when the answer takes none that matter
     * @param recorded what the recording answered, returned unchanged when nothing governs this key
     * @param now      the guest clock in milliseconds
     */
    Object answer(String key, String argument, Object recorded, long now) {
        Rule rule = rules.get(key);
        if (rule == null || rule.spec.getString("model") != null) {
            return recorded;
        }
        JSONObject spec = rule.spec;
        JSONObject byArgument = spec.getJSONObject("by_argument");
        if (byArgument != null) {
            if (argument == null || !byArgument.containsKey(argument)) {
                return recorded;        // a key of this call the data file says nothing about: as recorded
            }
            // each argument is its own value with its own history, so each gets its own rule
            String scoped = key + "#" + argument;
            Rule own = rules.get(scoped);
            if (own == null) {
                own = new Rule(rule.kind, merge(spec, byArgument.getJSONObject(argument)));
                rules.put(scoped, own);
            }
            rule = own;
            spec = own.spec;
        }

        if (rule.value == null) {
            rule.value = restore(key, argument, spec);
        }
        if ("occasionally_changes".equals(rule.kind)) {
            if (rule.nextChangeAt == Long.MIN_VALUE) {
                rule.nextChangeAt = now + nextInterval(spec);
            } else if (now >= rule.nextChangeAt) {
                // long gaps may cover several changes; the phone only ends up at one of them
                while (now >= rule.nextChangeAt) {
                    rule.nextChangeAt += nextInterval(spec);
                }
                rule.value = draw(spec, rule.value);
            }
        }
        return rule.value;
    }

    /** the value a per_install answer settled on, for the ledger to carry (so it is the same phone next launch) */
    JSONObject settled() {
        JSONObject out = new JSONObject(true);
        for (Map.Entry<String, Rule> entry : rules.entrySet()) {
            Rule rule = entry.getValue();
            if (rule.value != null && ("per_install".equals(rule.kind) || "occasionally_changes".equals(rule.kind))) {
                out.put(entry.getKey(), rule.value);
            }
        }
        return out;
    }

    /** this install's settled value from the ledger, or a fresh draw when it has none yet */
    private Object restore(String key, String argument, JSONObject spec) {
        JSONObject settled = ledger.getJSONObject("settled");
        String scoped = argument == null ? key : key + "#" + argument;
        if (settled != null && settled.get(scoped) != null) {
            return settled.get(scoped);
        }
        return draw(spec, null);
    }

    /**
     * One value from the rule. {@code avoid} is the value it is changing away from: a volume key press moves the volume, so
     * drawing the same number again would show up as a change that changed nothing.
     */
    private Object draw(JSONObject spec, Object avoid) {
        boolean integer = spec.getBooleanValue("integer");
        for (int attempt = 0; attempt < 8; attempt++) {
            Object value;
            JSONArray choices = spec.getJSONArray("choices");
            if (choices != null) {
                value = choices.get(random.nextInt(choices.size()));
            } else {
                JSONObject start = spec.getJSONObject("start");
                double drawn;
                if (start != null && start.containsKey("mode")) {
                    // a triangular draw: the middle of the range is where most phones sit
                    drawn = triangular(start.getDoubleValue("low"), start.getDoubleValue("high"),
                            start.getDoubleValue("mode"));
                } else {
                    double from = spec.getDoubleValue("from"), to = spec.getDoubleValue("to");
                    drawn = from + random.nextDouble() * (to - from);
                }
                value = integer ? (Object) (int) Math.round(drawn) : (Object) drawn;
            }
            if (avoid == null || !String.valueOf(avoid).equals(String.valueOf(value))) {
                return value;
            }
        }
        return avoid;
    }

    /** how long until the next change: around the stated mean, drawn so changes are not on a grid */
    private long nextInterval(JSONObject spec) {
        double meanMinutes = spec.getDoubleValue("mean_minutes_between_changes");
        if (meanMinutes <= 0) {
            return Long.MAX_VALUE / 4;
        }
        // an exponential wait: the memoryless gap of something that happens at a steady rate but not on a schedule
        double minutes = -meanMinutes * Math.log(1 - random.nextDouble());
        return (long) Math.max(1000, minutes * 60_000);
    }

    private double triangular(double low, double high, double mode) {
        double u = random.nextDouble(), split = (mode - low) / (high - low);
        return u < split ? low + Math.sqrt(u * (high - low) * (mode - low))
                : high - Math.sqrt((1 - u) * (high - low) * (high - mode));
    }

    /** an argument's own spec, over the defaults its call states */
    private static JSONObject merge(JSONObject base, JSONObject own) {
        JSONObject out = new JSONObject(true);
        out.putAll(base);
        out.remove("by_argument");
        out.putAll(own);
        return out;
    }
}
