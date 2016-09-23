import java.util.Map;

/**
 * Created by Senyang on 2016/2/29.
 * 
 * @author Senyang
 * @version 1.0
 */
public class JsonItem {
	private Map<Object, String> _id;
	private String ident;
	private Map<Object, String> timestamp;
	private boolean normalized;
	private Map<Object, String> payload;
	private String channel;
	private String type;

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public Map<Object, String> get_id() {
		return _id;
	}

	public void set_id(Map<Object, String> _id) {
		this._id = _id;
	}

	public Map<Object, String> getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Map<Object, String> timestamp) {
		this.timestamp = timestamp;
	}

	public Map<Object, String> getPayload() {
		return payload;
	}

	public void setPayload(Map<Object, String> payload) {
		this.payload = payload;
	}

	public String getIdent() {
		return ident;
	}

	public void setIdent(String ident) {
		this.ident = ident;
	}

	public boolean isNormalized() {
		return normalized;
	}

	public void setNormalized(boolean normalized) {
		this.normalized = normalized;
	}

	public String getChannel() {
		return channel;
	}

	public void setChannel(String channel) {
		this.channel = channel;
	}
}
