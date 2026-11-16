package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * The mssdk channel on the device's own clock. metasec drives it through {@code MS.b(0x30001)}: it hands Java a URL and a
 * body, Java does the request, and metasec reads the reply back. The recording holds all of that — which endpoint, what body,
 * and at which millisecond of the session it happened — so this tool replays the channel as it was worked:
 *
 * <pre>
 *   15.8 s  pilvinen/v1/sseelfk/haku   mode=2   configuration
 *   37.0 s  sdi/get_token              mode=2   the sdi token
 *   50.5 s  ri/report                  mode=3   environment report
 *   57.3 s  ri/report                  mode=3
 *   61.9 s  ri/report                  mode=3
 *   69.8 s  ri/report                  mode=3
 *  184.4 s  mscc/common_setting        mode=2
 * </pre>
 *
 * Registration does not carry any of this: {@code device_register} uploads the applog header, the environment goes out here,
 * on this channel, on its own timing — and on a first install it starts only after the registration (recorded: register at
 * 55.8 s, the first {@code get_token} at 60.2 s). The reports themselves are a startup burst, not a beat: four inside the
 * first 70 s of the session, then none for the remaining six minutes while 20 more signs happened. See
 * {@code doc/mssdk-channel.md} for the timeline and what each report carries.
 * <p>
 * Nothing is sent without {@code --live}; without it the timeline is only printed.
 * <p>
 * args: {@code [--live] [--scale <n>]}, where {@code --scale} divides the recorded offsets (e.g. {@code 10} turns the 70 s of
 * reports into 7 s) so a run does not have to wait the real thing.
 */
public class MssdkUpload {

    private static final File RESOURCES = Build.RESOURCES;
    private static final int NETWORK_CALLBACK = 0x30001;

    /** one {@code MS.b(0x30001)}: where it went, what went with it, and when in the recorded session */
    static final class Upload {

        final long atMillis;
        final String url;
        final byte[] body;

        Upload(long atMillis, String url, byte[] body) {
            this.atMillis = atMillis;
            this.url = url;
            this.body = body;
        }

        /** the endpoint as the field document names it: the path's last two segments, e.g. {@code sdi/get_token} */
        String channel() {
            String path = url.split("\\?", 2)[0].replace("https://", "");
            String[] parts = path.split("/");
            return parts.length >= 2 ? parts[parts.length - 2] + "/" + parts[parts.length - 1] : path;
        }

        String mode() {
            int at = url.indexOf("mode=");
            return at < 0 ? "-" : url.substring(at + 5, Math.min(at + 6, url.length()));
        }
    }

    public static void main(String[] args) throws Exception {
        boolean live = false;
        double scale = 1;
        for (int i = 0; i < args.length; i++) {
            if ("--live".equals(args[i])) {
                live = true;
            } else if ("--scale".equals(args[i]) && i + 1 < args.length) {
                scale = Double.parseDouble(args[++i]);
            }
        }
        List<Upload> timeline = timeline(new DeviceProfile(new File(RESOURCES, "device/fp_values_full.json")));
        System.out.printf("== the mssdk channel as recorded: %d uploads%s%n", timeline.size(),
                live ? " (live: they are sent at their recorded offsets)" : " (dry run: pass --live to send)");
        long start = System.currentTimeMillis();
        for (Upload upload : timeline) {
            long due = start + (long) (upload.atMillis * scale);
            long wait = due - System.currentTimeMillis();
            if (wait > 0 && live) {
                Thread.sleep(wait);
            }
            System.out.printf("== t=%6d ms  %-22s mode=%s  %6d bytes  %s%n", upload.atMillis, upload.channel(),
                    upload.mode(), upload.body.length, abbreviate(upload.url));
            if (live) {
                System.out.println(send(upload) ? "  PASS (the endpoint answered)" : "  FAILED");
            }
        }
        if (!live) {
            System.out.println("dry run: nothing was sent (pass --live to work the channel)");
        }
        System.exit(0);
    }

    /**
     * The {@code MS.b(0x30001)} records: {@code args.s} is the URL metasec built, {@code args.o} the Object[] it hands Java —
     * its first element is the request body, the same bytes that would go on the wire.
     */
    static List<Upload> timeline(DeviceProfile profile) throws DecoderException {
        List<Upload> uploads = new ArrayList<>();
        for (JSONObject record : profile.msb(NETWORK_CALLBACK)) {
            JSONObject args = record.getJSONObject("args");
            String url = args.getString("s");
            JSONArray parts = args.getJSONObject("o").getJSONArray("v");
            String hex = parts.getJSONObject(0).getString("hex");
            uploads.add(new Upload(record.getLongValue("t_ms"), url, Hex.decodeHex(hex.toCharArray())));
        }
        return uploads;
    }

    private static boolean send(Upload upload) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(upload.url).openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(20000);
        connection.setRequestProperty("Content-Type", "application/octet-stream");
        connection.setRequestProperty("Accept-Encoding", "gzip");
        connection.getOutputStream().write(upload.body);
        int code = connection.getResponseCode();
        InputStream stream = code >= 400 ? connection.getErrorStream() : connection.getInputStream();
        byte[] raw = stream == null ? new byte[0] : readAll(stream);
        System.out.printf("  HTTP %d, %d bytes back%s%n", code, raw.length,
                raw.length == 0 ? "" : ", " + abbreviate(new String(raw, StandardCharsets.ISO_8859_1)));
        return code == 200;
    }

    private static byte[] readAll(InputStream stream) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = stream.read(buffer)) > 0) {
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static String abbreviate(String text) {
        return text.length() <= 90 ? text : text.substring(0, 90) + "...";
    }

}
