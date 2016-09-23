import net.sf.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.*;
import java.util.*;

/**
 * Created by zhou on 2016/2/29.
 *
 * @author zhou
 * @version 1.0
 */
public class Parser {

    private String fileName = null;
    private List<String> keyList = new ArrayList<>();
    private List<String> valueList = new ArrayList<>();
    int size;
    private String args;
    CloseableHttpClient httpClient = HttpClients.createDefault();


    private List<JsonItem> resultList = new ArrayList<>();

    public void setArgs(String args) {
        this.args = args;
    }

    public List<String> getKeyList() {
        return keyList;
    }

    public List<String> getValueList() {
        return valueList;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public Parser(String fileName) {
        this.fileName = fileName;
    }

    public void storeFileInfo() throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new FileReader(new File(fileName)));
        String line;

        while ((line = bufferedReader.readLine()) != null) {
            JSONObject jsonObject = JSONObject.fromObject(line);
            JsonItem item = new JsonItem();
            Map<Object, String> idMap = new HashMap<>();
            Map<Object, String> timeMap = new HashMap<>();
            Map<Object, String> payMap = new HashMap<>();

            String ident = jsonObject.getString("ident");
            item.setIdent(ident);
            boolean normalized = jsonObject.getBoolean("normalized");
            item.setNormalized(normalized);
            String channel = jsonObject.getString("channel");
            item.setChannel(channel);

            JSONObject obj;
            String _id = jsonObject.getString("_id");
            obj = JSONObject.fromObject(_id);
            for (Object key : obj.keySet()) {
                idMap.put(key, obj.getString((String) key));
            }
            item.set_id(idMap);

            String timestamp = jsonObject.getString("timestamp");
            obj = JSONObject.fromObject(timestamp);
            for (Object key : obj.keySet()) {
                timeMap.put(key, obj.getString((String) key));
            }
            item.setTimestamp(timeMap);

            String payload = jsonObject.getString("payload");
            boolean hastype = false;
            payload = payload.substring(1, payload.length() - 1);
            obj = JSONObject.fromObject(payload);
            for (Object key : obj.keySet()) {
                payMap.put(key, obj.getString((String) key));

                if (!hastype && key.equals("filename")) {
                    item.setType("FILE_PATTERN");
                    hastype = true;
                }

                if (!hastype && key.equals("date")) {
                    item.setType("DESTINATION_SOURCE");
                    hastype = true;
                }

                if (!hastype && key.equals("attackerIP")) {
                    item.setType("ATTACKER_VICTIM");
                    hastype = true;
                }
            }
            if (!hastype) {
                item.setType("OTHERS");
            }
            item.setPayload(payMap);

            resultList.add(item);
        }
    }

    public void analyseFile() throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new FileReader(new File(fileName)));
        String line;

        while ((line = bufferedReader.readLine()) != null) {
            JSONObject jsonObject = JSONObject.fromObject(line);

            JSONObject obj;
            String timestamp = jsonObject.getString("timestamp");
            obj = JSONObject.fromObject(timestamp);
            String time = obj.getString("$date");

            String payload = jsonObject.getString("payload");
            payload = payload.substring(1, payload.length() - 1);
            obj = JSONObject.fromObject(payload);
            int fullFill = 0;
            for (Object key : obj.keySet()) {
                String sKey = (String) key;
                String value = obj.getString(sKey);
                for (int i = 0; i < size; i++) {
                    String k = keyList.get(i);
                    String v = valueList.get(i);
                    if (k.contains("ip")) {
                        if (value.toLowerCase().contains(v) && sKey.toLowerCase().contains(k)) {
                            fullFill++;
                        }
                    } else if (k.contains("port")) {
                        if (value.toLowerCase().equals(v) && sKey.toLowerCase().contains(k)) {
                            fullFill++;
                        }
                    }
                }
            }

            if (fullFill == size) {
                obj.put("timestamp", time);
                printRecord(obj);
            }
        }
    }

    private void printRecord(JSONObject object) {
        System.out.println("Infomation for " + args + " :");
        System.out.println("Source : Honeypot");
        System.out.println("{");
        Iterator it = object.keys();
        while (it.hasNext()) {
            String k = (String) it.next();
            String v = object.getString(k);
            System.out.println("\t" + k + " : " + v);
        }
        System.out.println("}\n");
    }

    public void apiResult() throws Exception {
        String basciURL = "http://isc.sans.edu/api/%s?json";

        for (int i = 0; i < keyList.size(); i++) {
            String key = keyList.get(i);
            if (key.contains("ip")) {
                String q = "ip/" + valueList.get(i);

                String query = String.format(basciURL, q);
                HttpGet httpGet = new HttpGet(query);
                CloseableHttpResponse response = httpClient.execute(httpGet);
                HttpEntity httpEntity = response.getEntity();
                InputStream inputStream = httpEntity.getContent();
                String str = convertStreamToString(inputStream);

                System.out.println("Analysis for ip-" + valueList.get(i) + " from API :");
                System.out.println("Source : https://isc.sans.edu/api/");
                System.out.println("{\n\tIP : {");
                JSONObject object = JSONObject.fromObject(str);
                object = JSONObject.fromObject(object.getString("ip"));
                Iterator it = object.keys();
                while (it.hasNext()) {
                    String k = (String) it.next();
                    if (k.equals("threatfeeds")) {
                        JSONObject feeds = JSONObject.fromObject(object.getString("threatfeeds"));
                        System.out.println("\t\tthreatfeeds : {");
                        Iterator nit = feeds.keys();
                        while (nit.hasNext()) {
                            String fk = (String) nit.next();
                            String fv = feeds.getString(fk);
                            System.out.println("\t\t\t" + fk + " : " + fv);
                        }
                        System.out.println("\t\t},");
                    } else {
                        String v = object.getString(k);
                        System.out.println("\t\t" +k + " : " + v);
                    }
                }
                System.out.println("\t}\n}\n");
            }

            if (key.contains("port")) {
                String q = "port/" + valueList.get(i);

                String query = String.format(basciURL, q);
                HttpGet httpGet = new HttpGet(query);
                CloseableHttpResponse response = httpClient.execute(httpGet);
                HttpEntity httpEntity = response.getEntity();
                InputStream inputStream = httpEntity.getContent();
                String str = convertStreamToString(inputStream);
                Iterator it;

                System.out.println("Analysis for port-" + valueList.get(i) + " from API :");
                System.out.println("Source : https://isc.sans.edu/api/");
                System.out.println("{");
                JSONObject object = JSONObject.fromObject(str);
                System.out.println("\tnumber : " + object.getString("number") + "\n\tdata : {");
                JSONObject data = JSONObject.fromObject(object.getString("data"));
                for (Object obj : data.keySet()) {
                    System.out.println("\t\t" + obj + " : " + data.getString((String) obj));
                }
                System.out.println("\t},\n\tservices : {");
                JSONObject services = JSONObject.fromObject(object.getString("services"));
                JSONObject udp = JSONObject.fromObject(services.getString("udp"));
                JSONObject tcp = JSONObject.fromObject(services.getString("tcp"));

                System.out.println("\t\tudp : {");
                it = udp.keys();
                while (it.hasNext()) {
                    String k = (String) it.next();
                    String v = udp.getString(k);
                    System.out.println("\t\t\t" + k + " : " + v);
                }
                System.out.println("\t\t},\n\t\ttcp : {");
                it = tcp.keys();
                while (it.hasNext()) {
                    String k = (String) it.next();
                    String v = tcp.getString(k);
                    System.out.println("\t\t\t" + k + " : " + v);
                }
                System.out.println("\t\t}\n\t}\n}");

                System.out.println();
            }
        }

    }

    private static String convertStreamToString(InputStream inputStream) throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder sb = new StringBuilder();

        String line;
        while ((line = bufferedReader.readLine()) != null) {
            sb.append(line).append("\n");
        }

        bufferedReader.close();
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String file = "honeypot1.json";
        Parser parser = new Parser(file);
        String p = "";

        parser.setSize(args.length);
        for (String str : args) {
            p += str.toLowerCase().trim() + ", ";
            String[] s = str.trim().split(":");
            parser.getKeyList().add(s[0].toLowerCase().trim());
            parser.getValueList().add(s[1].toLowerCase().trim());
        }

        p = p.trim().substring(0, p.length() - 2);
        parser.setArgs(p);

        parser.apiResult();
        parser.analyseFile();
    }
}
