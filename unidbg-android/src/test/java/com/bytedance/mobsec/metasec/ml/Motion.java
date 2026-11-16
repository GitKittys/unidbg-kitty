package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * The accelerometer this install reports, as a series rather than a value.
 *
 * <p>metasec polls {@code MS.b(0x1000013)} on a 10-second timer and expects back the samples taken since the last poll,
 * {@code |}-separated; it then stamps each with a millisecond and reports them under {@code acc} in report field
 * {@code /#9/#3} (doc/mssdk-report-fields.md). Only sampling slot 1 is ever written, so {@code gyro} and {@code euler} stay
 * empty and the accelerometer carries the whole signal.
 *
 * <p>What that means is that the risk model is not shown a number, it is shown a phone's recent history. The recording is of
 * a phone lying still on a table (1 g at a constant 2.11° from flat), and the replay clamps to the last recorded answer, so
 * after the third poll the series repeats two values for the rest of the session - an accelerometer that has stopped moving
 * while the app keeps being used. A real device being held produces small continuous change; one set down produces a new
 * resting attitude and then near-silence; neither produces two frozen numbers forever.
 *
 * <p>This class is only the physics: gravity projected onto the device's current attitude, plus the noise of whatever the
 * phone is doing. Every quantity - the attitude an owner leaves it at, how each activity behaves, how activities follow one
 * another, the stride cadence - is read from {@code device/motion.json} and none of it is written here, so the model can be
 * corrected from data without touching this code.
 */
class Motion {

    /** one activity's behaviour, as the data file states it */
    private static final class Activity {
        private final String name;
        /** per-sample noise (m/s²) */
        private final double noise;
        /** how fast the attitude itself wanders (radians per second) */
        private final double drift;
        /** the chance a poll window keeps this activity rather than changing */
        private final double stickiness;
        /** what it becomes when it does change: name -> share */
        private final Map<String, Double> transitions = new java.util.LinkedHashMap<>();

        private Activity(String name, JSONObject values) {
            this.name = name;
            this.noise = values.getDoubleValue("noise");
            this.drift = values.getDoubleValue("drift");
            this.stickiness = values.getDoubleValue("stickiness");
            for (Map.Entry<String, Object> to : values.getJSONObject("transitions").entrySet()) {
                transitions.put(to.getKey(), Double.parseDouble(String.valueOf(to.getValue())));
            }
        }
    }

    private final Random random;
    private final double gravity;
    private final long sampleMs;
    private final int maxSamples;
    private final boolean firstPollEmpty;
    private final double strideHz;
    private final double strideSpread;
    private final double strideAmplitude;
    private final double settleFrom;
    private final double settleTo;
    private final Map<String, Activity> activities = new java.util.LinkedHashMap<>();

    /** the device's attitude: how far from flat, and which way it leans */
    private double tilt;
    private double facing;
    private Activity activity;
    /** the walking cadence's phase, so consecutive samples of a walk belong to one stride */
    private double stride;
    /** the guest moment the last sample was taken: the series is paced by the clock, not by the call count */
    private long sampledAt = -1;
    private int polls;

    /**
     * One install's own phone, from the data file. The attitude it starts at is where its owner leaves it and the activity is
     * what they are doing when the session opens - both drawn from the shares the file states.
     */
    Motion(File dataFile, Random random) throws IOException {
        this.random = random;
        JSONObject data = JSONObject.parseObject(
                org.apache.commons.io.FileUtils.readFileToString(dataFile, java.nio.charset.StandardCharsets.UTF_8));
        this.gravity = data.getDoubleValue("gravity");
        this.sampleMs = data.getLongValue("sample_ms");
        this.maxSamples = data.getIntValue("max_samples_per_poll");
        this.firstPollEmpty = data.getBooleanValue("first_poll_empty");
        this.strideHz = data.getDoubleValue("stride_hz");
        this.strideSpread = data.getDoubleValue("stride_hz_spread");
        this.strideAmplitude = data.getDoubleValue("stride_amplitude");
        this.settleFrom = data.getDoubleValue("settle_tilt_from");
        this.settleTo = data.getDoubleValue("settle_tilt_to");
        for (Map.Entry<String, Object> entry : data.getJSONObject("activities").entrySet()) {
            activities.put(entry.getKey(), new Activity(entry.getKey(), (JSONObject) entry.getValue()));
        }

        JSONArray attitudes = data.getJSONArray("resting_attitude");
        JSONObject band = (JSONObject) attitudes.get(attitudes.size() - 1);
        double roll = random.nextDouble();
        double seen = 0;
        for (int i = 0; i < attitudes.size(); i++) {
            JSONObject candidate = (JSONObject) attitudes.get(i);
            seen += candidate.getDoubleValue("share");
            if (roll <= seen) {
                band = candidate;
                break;
            }
        }
        this.tilt = Math.toRadians(between(band.getDoubleValue("tilt_from"), band.getDoubleValue("tilt_to")));
        this.facing = random.nextDouble() * 2 * Math.PI;
        this.activity = pick(shares(data.getJSONObject("initial_activity")));
        this.stride = random.nextDouble() * 2 * Math.PI;
    }

    /** the current attitude in degrees from flat, for the run's own report */
    double tiltDegrees() {
        return Math.toDegrees(tilt);
    }

    String activity() {
        return activity.name;
    }

    /**
     * The samples taken since the last poll, in the encoding the callback answers with ({@code x,y,z} per sample,
     * {@code |}-separated, two decimals as the device reports them), or null for a first poll whose buffer has not filled.
     *
     * <p>{@code now} is the guest clock, so the number of samples follows the time the app has actually been running rather
     * than how many times this was called: a poll after a long gap carries more of them, as the device's own buffer would.
     */
    String sample(long now) {
        if (++polls == 1 && firstPollEmpty) {
            sampledAt = now;
            return null;
        }
        if (sampledAt < 0) {
            sampledAt = now - sampleMs;
        }
        long elapsed = Math.max(0, now - sampledAt);
        int count = (int) Math.min(maxSamples, Math.max(1, elapsed / sampleMs));
        advance();
        List<String> samples = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            samples.add(one(sampleMs / 1000.0));
        }
        sampledAt = now;
        return String.join("|", samples);
    }

    /**
     * The phone between two polls: it may have been picked up, put down, or carried. Changing only at a poll boundary is
     * coarse, but a poll is 10 seconds and people do not change what they are doing faster than that for long.
     */
    private void advance() {
        if (random.nextDouble() < activity.stickiness) {
            return;
        }
        Activity was = activity;
        activity = pick(activity.transitions);
        if (activity != was && "resting".equals(activity.name)) {
            // put down: it comes to rest at a new attitude, not the one it had in the hand
            tilt = Math.toRadians(between(settleFrom, settleTo));
            facing = random.nextDouble() * 2 * Math.PI;
        }
    }

    /** one sample: gravity projected onto the attitude the device has now, plus this activity's own noise */
    private String one(double seconds) {
        // the attitude wanders while the phone is handled; a resting phone's hardly moves at all
        tilt += random.nextGaussian() * activity.drift * seconds;
        facing += random.nextGaussian() * activity.drift * 2 * seconds;
        tilt = Math.max(0, Math.min(Math.PI / 2, tilt));

        double magnitude = gravity;
        if (strideAmplitude > 0 && "walking".equals(activity.name)) {
            stride += 2 * Math.PI * (strideHz + random.nextGaussian() * strideSpread) * seconds;
            magnitude += Math.sin(stride) * strideAmplitude;
        }
        // gravity in the device's own frame: tilted away from flat, leaning the way it faces
        double x = magnitude * Math.sin(tilt) * Math.cos(facing) + random.nextGaussian() * activity.noise;
        double y = magnitude * Math.sin(tilt) * Math.sin(facing) + random.nextGaussian() * activity.noise;
        double z = magnitude * Math.cos(tilt) + random.nextGaussian() * activity.noise;
        return String.format("%.2f,%.2f,%.2f", x, y, z);
    }

    private Map<String, Double> shares(JSONObject values) {
        Map<String, Double> out = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            out.put(entry.getKey(), Double.parseDouble(String.valueOf(entry.getValue())));
        }
        return out;
    }

    /** one activity, by the shares the data file gives */
    private Activity pick(Map<String, Double> shares) {
        double roll = random.nextDouble() * total(shares);
        double seen = 0;
        String last = null;
        for (Map.Entry<String, Double> entry : shares.entrySet()) {
            last = entry.getKey();
            seen += entry.getValue();
            if (roll <= seen) {
                return named(entry.getKey());
            }
        }
        return named(last);
    }

    private static double total(Map<String, Double> shares) {
        double sum = 0;
        for (double share : shares.values()) {
            sum += share;
        }
        return sum > 0 ? sum : 1;
    }

    private Activity named(String name) {
        Activity found = activities.get(name);
        if (found == null) {
            throw new IllegalStateException("motion.json names the activity " + name + ", which it does not define");
        }
        return found;
    }

    private double between(double from, double to) {
        return from + random.nextDouble() * (to - from);
    }
}
