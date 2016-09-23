import net.sf.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Created by Senyang on 2016/2/29.
 *
 * @author Senyang
 * @version 2.0
 */
public class Parser {

	private String fileName = null;
	private List<List<String>> keyList = new ArrayList<>();
	private List<List<String>> valueList = new ArrayList<>();
	private List<Integer> argCount = new ArrayList<>();
	int size;
	private List<String> args = new ArrayList<>();
	CloseableHttpClient httpClient = HttpClients.createDefault();

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public List<String> getArgs() {
		return args;
	}

	public List<List<String>> getKeyList() {
		return keyList;
	}

	public List<List<String>> getValueList() {
		return valueList;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public void sizeReduce() {
		size--;
	}

	public Parser(String fileName) {
		this.fileName = fileName;
	}

	public void analyseFile() throws Exception {
		genArgCount();
		BufferedReader bufferedReader = new BufferedReader(new FileReader(
				new File(fileName)));
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

			List<Integer> ct = new ArrayList<>();
			for (int i = 0; i < size; i++) {
				ct.add(0);
			}

			for (Object key : obj.keySet()) {
				String sKey = (String) key;
				String value = obj.getString(sKey);
				for (int i = 0; i < size; i++) {
					List<String> kLIst = keyList.get(i);
					List<String> vList = valueList.get(i);
					int kSize = argCount.get(i);

					for (int j = 0; j < kSize; j++) {
						String k = kLIst.get(j);
						String v = vList.get(j);
						if (k.contains("port")) {
							if (value.toLowerCase().equals(v)
									&& sKey.toLowerCase().contains(k)) {
								int t = ct.get(i);
								ct.set(i, ++t);
							}
						} else {
							if (value.toLowerCase().contains(v)
									&& sKey.toLowerCase().contains(k)) {
								int t = ct.get(i);
								ct.set(i, ++t);
							}
						}
					}

				}
			}

			for (int i = 0; i < size; i++) {
				int fullFill = argCount.get(i);
				int cur = ct.get(i);
				if (fullFill == cur) {
					obj.put("timestamp", time);
					printRecord(obj, i);
				}
			}

			for (int i = 0; i < ct.size(); i++) {
				ct.set(i, 0);
			}
		}
	}

	private void printRecord(JSONObject object, int index) {
		String arg = args.get(index);
		System.out.println("Infomation for " + arg + " :");
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

	private void genArgCount() {
		argCount.addAll(keyList.stream().map(List<String>::size)
				.collect(Collectors.toList()));
	}

	public void apiResult() throws Exception {
		String basciURL = "http://isc.sans.edu/api/%s?json";

		for (int i = 0; i < keyList.size(); i++) {
			List<String> kList = keyList.get(i);
			List<String> vList = valueList.get(i);

			for (int j = 0; j < kList.size(); j++) {
				String key = kList.get(j);
				if (key.contains("ip")) {
					String q = "ip/" + vList.get(j);

					String query = String.format(basciURL, q);
					HttpGet httpGet = new HttpGet(query);
					CloseableHttpResponse response = httpClient
							.execute(httpGet);
					HttpEntity httpEntity = response.getEntity();
					InputStream inputStream = httpEntity.getContent();
					String str = convertStreamToString(inputStream);

					System.out.println("Analysis for ip-" + vList.get(j)
							+ " for PARAM-< " + args.get(i) + " > :");
					System.out.println("Source : https://isc.sans.edu/api/");
					System.out.println("{\n\tIP : {");
					JSONObject object = JSONObject.fromObject(str);
					object = JSONObject.fromObject(object.getString("ip"));
					Iterator it = object.keys();
					while (it.hasNext()) {
						String k = (String) it.next();
						if (k.equals("threatfeeds")) {
							JSONObject feeds = JSONObject.fromObject(object
									.getString("threatfeeds"));
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
							System.out.println("\t\t" + k + " : " + v);
						}
					}
					System.out.println("\t}\n}\n");
				}

				if (key.contains("port")) {
					String q = "port/" + vList.get(j);

					String query = String.format(basciURL, q);
					HttpGet httpGet = new HttpGet(query);
					CloseableHttpResponse response = httpClient
							.execute(httpGet);
					HttpEntity httpEntity = response.getEntity();
					InputStream inputStream = httpEntity.getContent();
					String str = convertStreamToString(inputStream);
					Iterator it;

					System.out.println("Analysis for port-" + vList.get(j)
							+ " for PARAM-< " + args.get(i) + " > :");
					System.out.println("Source : https://isc.sans.edu/api/");
					System.out.println("{");
					JSONObject object = JSONObject.fromObject(str);
					System.out.println("\tnumber : "
							+ object.getString("number") + "\n\tdata : {");
					JSONObject data = JSONObject.fromObject(object
							.getString("data"));
					for (Object obj : data.keySet()) {
						System.out.println("\t\t" + obj + " : "
								+ data.getString((String) obj));
					}
					System.out.println("\t},\n\tservices : {");
					JSONObject services = JSONObject.fromObject(object
							.getString("services"));
					JSONObject udp = JSONObject.fromObject(services
							.getString("udp"));
					JSONObject tcp = JSONObject.fromObject(services
							.getString("tcp"));

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
	}

	private String convertStreamToString(InputStream inputStream)
			throws Exception {
		BufferedReader bufferedReader = new BufferedReader(
				new InputStreamReader(inputStream));
		StringBuilder sb = new StringBuilder();

		String line;
		while ((line = bufferedReader.readLine()) != null) {
			sb.append(line).append("\n");
		}

		bufferedReader.close();
		return sb.toString();
	}

	public static void main(String[] args) throws Exception {
		String file = "honeypot.json";
		Parser parser = new Parser(file);

		parser.setSize(args.length);
		for (String str : args) {
			boolean isFIle = false;
			List<String> kList = new ArrayList<>();
			List<String> vList = new ArrayList<>();
			String[] para = str.trim().split(",");
			for (String temp : para) {
				String[] n = temp.trim().split(":");
				if (n[0].equalsIgnoreCase("file")) {
					isFIle = true;
					parser.setFileName(n[1].trim());
					parser.sizeReduce();
				} else {
					kList.add(n[0].toLowerCase().trim());
					vList.add(n[1].toLowerCase().trim());
				}
			}
			if (!isFIle) {
				parser.getKeyList().add(kList);
				parser.getValueList().add(vList);
				parser.getArgs().add(str.toLowerCase().trim());
			}
		}
		System.out
				.println("*******************     Analyse from local file     *******************\n");
		parser.analyseFile();
		System.out
				.println("\n***********************     Analysis from API     ***********************\n");
		parser.apiResult();

		System.out
				.println("******************************     END     ******************************");
	}
}
